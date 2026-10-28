//! Same-address binary reload, not a signed loader upgrade.
//! V1 instructions and account decoding use the frozen baseline client.
//! A separate hand-encoded V2 probe distinguishes old from new runtime execution.
use base64::{Engine, engine::general_purpose::STANDARD};
use payment_channels_client::{accounts::Channel, instructions::*, types::*};
use serde_json::{Value, json};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::{
    io::Write,
    process::{Command, Stdio},
    str::FromStr,
    thread::sleep,
    time::Duration,
};

fn id(s: &str) -> Pubkey {
    Pubkey::from_str(s).unwrap()
}
fn program() -> Pubkey {
    payment_channels_client::programs::PAYMENT_CHANNELS_ID
}
fn token() -> Pubkey {
    id("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}
fn associated() -> Pubkey {
    id("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}
fn sysvar() -> Pubkey {
    id("Sysvar1nstructions1111111111111111111111111")
}
fn event() -> Pubkey {
    Pubkey::find_program_address(&[b"event_authority"], &program()).0
}
fn ata(owner: Pubkey, mint: Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token().as_ref(), mint.as_ref()],
        &associated(),
    )
    .0
}
fn rw(key: Pubkey) -> AccountMeta {
    AccountMeta::new(key, false)
}
fn ro(key: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}

struct Rpc(String);
impl Rpc {
    fn call(&self, method: &str, params: Value) -> Value {
        let mut child = Command::new("curl")
            .args([
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "30",
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                &self.0,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
                    .to_string()
                    .as_bytes(),
            )
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{method}: transport");
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(response.get("error").is_none(), "{method}: {response}");
        response["result"].clone()
    }
    fn account(&self, key: Pubkey) -> Value {
        self.call(
            "getAccountInfo",
            json!([key.to_string(), {"encoding":"base64","commitment":"confirmed"}]),
        )["value"]
            .clone()
    }
    fn data(&self, key: Pubkey) -> Vec<u8> {
        STANDARD
            .decode(
                self.account(key)["data"][0]
                    .as_str()
                    .expect("account exists"),
            )
            .unwrap()
    }
    fn balance(&self, key: Pubkey) -> u64 {
        u64::from_le_bytes(self.data(key)[64..72].try_into().unwrap())
    }
    fn send(&self, label: &str, ixs: &[Instruction], payer: &Keypair, signers: &[&Keypair]) {
        self.send_expect(label, ixs, payer, signers, Value::Null);
    }
    fn send_expect(
        &self,
        label: &str,
        ixs: &[Instruction],
        payer: &Keypair,
        signers: &[&Keypair],
        expected_error: Value,
    ) {
        let hash = self.call("getLatestBlockhash", json!([{"commitment":"confirmed"}]))["value"]["blockhash"].as_str().unwrap().to_owned();
        let tx = Transaction::new_signed_with_payer(
            ixs,
            Some(&payer.pubkey()),
            signers,
            hash.parse().unwrap(),
        );
        let wire = bincode::serialize(&tx).unwrap();
        assert!(wire.len() <= 1232);
        let sim = self.call("simulateTransaction", json!([STANDARD.encode(&wire), {"encoding":"base64","sigVerify":true,"commitment":"confirmed"}]));
        assert_eq!(sim["value"]["err"], expected_error, "{label}: {sim}");
        // Submit the old runtime's expected rejection too, then inspect ledger state.
        let signature = self.call("sendTransaction", json!([STANDARD.encode(wire), {"encoding":"base64","skipPreflight":true,"preflightCommitment":"confirmed"}])).as_str().unwrap().to_owned();
        for _ in 0..100 {
            let status =
                self.call("getSignatureStatuses", json!([[signature]]))["value"][0].clone();
            if !status.is_null() {
                assert_eq!(status["err"], expected_error, "{label}: {status}");
                if matches!(
                    status["confirmationStatus"].as_str(),
                    Some("confirmed" | "finalized")
                ) {
                    println!("PASS {label}: {signature}");
                    return;
                }
            }
            sleep(Duration::from_millis(100));
        }
        panic!("{label}: confirmation timeout");
    }
    fn load(&self, variable: &str) {
        let bytes = std::fs::read(std::env::var(variable).unwrap()).unwrap();
        assert_eq!(&bytes[..4], b"\x7fELF");
        self.call(
            "surfnet_writeProgram",
            json!([program().to_string(), hex::encode(bytes), 0]),
        );
        assert_eq!(self.account(program())["executable"], true);
    }
}

struct Fixture<'a> {
    rpc: &'a Rpc,
    payer: Keypair,
    payee: Keypair,
    mint: Pubkey,
    channel: Pubkey,
    escrow: Pubkey,
    payer_ata: Pubkey,
    payee_ata: Pubkey,
    treasury_ata: Pubkey,
    slot: u64,
    salt: u64,
}
impl<'a> Fixture<'a> {
    fn new(rpc: &'a Rpc, salt: u64) -> Self {
        let payer = Keypair::new();
        let payee = Keypair::new();
        let mint = Keypair::new();
        rpc.call(
            "requestAirdrop",
            json!([payer.pubkey().to_string(), 10_000_000_000u64]),
        );
        let rent = rpc
            .call("getMinimumBalanceForRentExemption", json!([82]))
            .as_u64()
            .unwrap();
        let mut create = 0u32.to_le_bytes().to_vec();
        create.extend(rent.to_le_bytes());
        create.extend(82u64.to_le_bytes());
        create.extend(token().to_bytes());
        let mut initialize = vec![20, 0];
        initialize.extend(payer.pubkey().to_bytes());
        initialize.push(0);
        rpc.send(
            "create mint",
            &[
                Instruction {
                    program_id: Pubkey::default(),
                    accounts: vec![
                        AccountMeta::new(payer.pubkey(), true),
                        AccountMeta::new(mint.pubkey(), true),
                    ],
                    data: create,
                },
                Instruction {
                    program_id: token(),
                    accounts: vec![rw(mint.pubkey())],
                    data: initialize,
                },
            ],
            &payer,
            &[&payer, &mint],
        );
        let treasury =
            Pubkey::new_from_array(std::array::from_fn(
                |i| if i % 2 == 0 { 0xbe } else { 0xef },
            ));
        for owner in [payer.pubkey(), payee.pubkey(), treasury] {
            rpc.send(
                "create ATA",
                &[Instruction {
                    program_id: associated(),
                    accounts: vec![
                        AccountMeta::new(payer.pubkey(), true),
                        rw(ata(owner, mint.pubkey())),
                        ro(owner),
                        ro(mint.pubkey()),
                        ro(Pubkey::default()),
                        ro(token()),
                    ],
                    data: vec![1],
                }],
                &payer,
                &[&payer],
            );
        }
        let payer_ata = ata(payer.pubkey(), mint.pubkey());
        let mut mint_to = vec![7];
        mint_to.extend(10_000u64.to_le_bytes());
        rpc.send(
            "mint 10000",
            &[Instruction {
                program_id: token(),
                accounts: vec![
                    rw(mint.pubkey()),
                    rw(payer_ata),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                ],
                data: mint_to,
            }],
            &payer,
            &[&payer],
        );
        let slot = rpc
            .call("getSlot", json!([{"commitment":"confirmed"}]))
            .as_u64()
            .unwrap();
        let channel = Pubkey::find_program_address(
            &[
                b"channel",
                payer.pubkey().as_ref(),
                payee.pubkey().as_ref(),
                mint.pubkey().as_ref(),
                payer.pubkey().as_ref(),
                &salt.to_le_bytes(),
                &slot.to_le_bytes(),
            ],
            &program(),
        )
        .0;
        Self {
            rpc,
            payer_ata,
            payee_ata: ata(payee.pubkey(), mint.pubkey()),
            treasury_ata: ata(treasury, mint.pubkey()),
            escrow: ata(channel, mint.pubkey()),
            channel,
            mint: mint.pubkey(),
            payer,
            payee,
            salt,
            slot,
        }
    }
    fn recipients(&self) -> Vec<DistributionEntry> {
        vec![DistributionEntry {
            recipient: self.payee.pubkey(),
            bps: 10_000,
        }]
    }
    fn send(&self, label: &str, ix: Instruction) {
        self.rpc.send(label, &[ix], &self.payer, &[&self.payer]);
    }
    fn open_instruction(&self) -> Instruction {
        Open {
            payer: self.payer.pubkey(),
            rent_payer: self.payer.pubkey(),
            payee: self.payee.pubkey(),
            mint: self.mint,
            authorized_signer: self.payer.pubkey(),
            channel: self.channel,
            payer_token_account: self.payer_ata,
            channel_token_account: self.escrow,
            token_program: token(),
            system_program: Pubkey::default(),
            rent: id("SysvarRent111111111111111111111111111111111"),
            associated_token_program: associated(),
            event_authority: event(),
            self_program: program(),
        }
        .instruction(OpenInstructionArgs {
            open_args: OpenArgs {
                salt: self.salt,
                deposit: 1_000,
                grace_period: 3600,
                open_slot: self.slot,
                recipients: self.recipients(),
            },
        })
    }
    fn open(&self) {
        let ix = self.open_instruction();
        assert_eq!(ix.data[0], 1);
        self.send("frozen client open V1", ix);
        self.state(1_000, 0, 0);
    }
    fn state(&self, deposit: u64, settled: u64, paid: u64) {
        let bytes = self.rpc.data(self.channel);
        assert_eq!(bytes.len(), 256, "V1 stays exactly 256 bytes");
        let ch = Channel::from_bytes(&bytes).unwrap();
        assert_eq!(ch.version, 1);
        assert_eq!(ch.deposit, deposit);
        assert_eq!(ch.settlement.settled, settled);
        assert_eq!(ch.settlement.payout_watermark, paid);
        assert_eq!(ch.payer, self.payer.pubkey());
        assert_eq!(ch.payee, self.payee.pubkey());
        assert_eq!(ch.mint, self.mint);
        assert_eq!(ch.salt, self.salt);
        assert_eq!(ch.open_slot, self.slot);
        assert_eq!(
            self.rpc.account(self.channel)["owner"],
            program().to_string()
        );
    }
    fn voucher(&self, amount: u64) -> Instruction {
        let message = borsh::to_vec(&VoucherArgs {
            magic: [0x56, 1],
            channel_id: self.channel,
            cumulative_amount: amount,
            expires_at: 0,
        })
        .unwrap();
        let signature = self.payer.sign_message(&message);
        let mut data = vec![1, 0];
        for n in [
            48u16,
            u16::MAX,
            16,
            u16::MAX,
            112,
            message.len() as u16,
            u16::MAX,
        ] {
            data.extend(n.to_le_bytes());
        }
        data.extend(self.payer.pubkey().to_bytes());
        data.extend(signature.as_ref());
        data.extend(message);
        Instruction {
            program_id: id("Ed25519SigVerify111111111111111111111111111"),
            accounts: vec![],
            data,
        }
    }
    fn settle(&self, voucher: Instruction) {
        self.rpc.send(
            "frozen voucher settle",
            &[
                voucher,
                Settle {
                    channel: self.channel,
                    instructions_sysvar: sysvar(),
                }
                .instruction(),
            ],
            &self.payer,
            &[&self.payer],
        );
    }
    fn distribute(&self) {
        let ix = Distribute {
            channel: self.channel,
            payer: self.payer.pubkey(),
            rent_payer: self.payer.pubkey(),
            channel_token_account: self.escrow,
            payer_token_account: self.payer_ata,
            payee_token_account: self.payee_ata,
            treasury_token_account: self.treasury_ata,
            mint: self.mint,
            token_program: token(),
            event_authority: event(),
            self_program: program(),
        }
        .instruction_with_remaining_accounts(
            DistributeInstructionArgs {
                distribute_args: DistributeArgs {
                    recipients: self.recipients(),
                },
            },
            &[rw(self.payee_ata)],
        );
        assert_eq!(ix.data[0], 7);
        self.send("frozen client distribute", ix);
    }
    fn finish(&self, retained_voucher: Instruction) {
        let top_up = TopUp {
            payer: self.payer.pubkey(),
            channel: self.channel,
            payer_token_account: self.payer_ata,
            channel_token_account: self.escrow,
            mint: self.mint,
            token_program: token(),
        }
        .instruction(TopUpInstructionArgs {
            top_up_args: TopUpArgs { amount: 500 },
        });
        assert_eq!(top_up.data[0], 3);
        self.send("frozen client top up 500", top_up);
        self.settle(retained_voucher);
        self.state(1_500, 700, 200);
        assert_eq!(self.rpc.balance(self.escrow), 1_300);
        self.rpc.send(
            "frozen client cooperative seal",
            &[SettleAndSeal {
                payee: self.payee.pubkey(),
                channel: self.channel,
                instructions_sysvar: sysvar(),
            }
            .instruction(SettleAndSealInstructionArgs {
                settle_and_seal_args: SettleAndSealArgs { has_voucher: 0 },
            })],
            &self.payer,
            &[&self.payer, &self.payee],
        );
        let withdraw = WithdrawPayer {
            payer: self.payer.pubkey(),
            channel: self.channel,
            channel_token_account: self.escrow,
            payer_token_account: self.payer_ata,
            mint: self.mint,
            token_program: token(),
        }
        .instruction();
        assert_eq!(withdraw.data[0], 8);
        self.send("frozen client refund 800", withdraw);
        assert_eq!(self.rpc.balance(self.payer_ata), 9_300);
        assert_eq!(self.rpc.balance(self.escrow), 500);
        self.distribute();
        assert_eq!(self.rpc.balance(self.payer_ata), 9_300);
        assert_eq!(self.rpc.balance(self.payee_ata), 700);
        assert_eq!(self.rpc.balance(self.treasury_ata), 0);
        // Distribution closes token custody immediately. The historical open-slot
        // replay window can retain an inert channel PDA until permissionless reclaim.
        if !self.rpc.account(self.channel).is_null() {
            // Terminal distribution does not advance the OPEN payout watermark.
            self.state(1_500, 700, 200);
            let ch = Channel::from_bytes(&self.rpc.data(self.channel)).unwrap();
            assert_eq!(ch.status, ChannelStatus::Distributed as u8);
            let mut unlocked = false;
            for _ in 0..600 {
                let slot = self
                    .rpc
                    .call("getSlot", json!([{"commitment":"confirmed"}]))
                    .as_u64()
                    .unwrap();
                if slot > self.slot + 1_500 {
                    unlocked = true;
                    break;
                }
                sleep(Duration::from_millis(100));
            }
            assert!(unlocked, "historical open-slot window did not expire");
            self.send(
                "frozen client reclaim after replay window",
                Reclaim {
                    channel: self.channel,
                    rent_payer: self.payer.pubkey(),
                }
                .instruction(),
            );
        }
        assert!(self.rpc.account(self.channel).is_null(), "channel closed");
        assert!(self.rpc.account(self.escrow).is_null(), "escrow closed");
    }
    fn partially_use(&self) {
        self.open();
        self.settle(self.voucher(200));
        self.distribute();
        self.state(1_000, 200, 200);
        assert_eq!(self.rpc.balance(self.payer_ata), 9_000);
        assert_eq!(self.rpc.balance(self.payee_ata), 200);
        assert_eq!(self.rpc.balance(self.escrow), 800);
    }
}

fn main() {
    let endpoint = std::env::var("UPGRADE_RPC").expect("run run.sh");
    endpoint
        .strip_prefix("http://127.0.0.1:")
        .expect("loopback only")
        .parse::<u16>()
        .expect("port only");
    let rpc = Rpc(endpoint);
    assert_eq!(
        program().to_string(),
        "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"
    );
    rpc.load("UPGRADE_OLD_SO");
    let old = Fixture::new(&rpc, 1);
    old.partially_use();
    let probe = Fixture::new(&rpc, 3);
    // Independent V2 wire fixture: the common Open prefix followed by four
    // disabled sparse hook descriptors. This is NOT an old-client V2 API.
    let mut hooked_open = probe.open_instruction();
    hooked_open.data[0] = 10;
    hooked_open.data.extend([0; 4]);
    rpc.send_expect(
        "old ELF rejects V2 discriminator 10",
        &[hooked_open.clone()],
        &probe.payer,
        &[&probe.payer],
        json!({"InstructionError":[0,"InvalidInstructionData"]}),
    );
    assert!(rpc.account(probe.channel).is_null());
    assert!(rpc.account(probe.escrow).is_null());
    assert_eq!(rpc.balance(probe.payer_ata), 10_000);
    // The Ed25519 signature exists before the binary swap and is never regenerated.
    let retained = old.voucher(700);
    let addresses = [
        old.channel,
        old.escrow,
        old.payer_ata,
        old.payee_ata,
        old.treasury_ata,
    ];
    let snapshots: Vec<_> = addresses.iter().map(|a| rpc.account(*a)).collect();
    rpc.load("UPGRADE_NEW_SO");
    for (address, before) in addresses.into_iter().zip(snapshots) {
        assert_eq!(
            rpc.account(address),
            before,
            "binary reload changed account {address}"
        );
    }
    println!("PASS same-address reload preserves complete V1 and token accounts");
    probe.send("new ELF accepts identical V2 discriminator 10", hooked_open);
    let hooked_bytes = rpc.data(probe.channel);
    assert_eq!(hooked_bytes.len(), 1121);
    assert_eq!(hooked_bytes[1], 2);
    assert_eq!(rpc.balance(probe.payer_ata), 9_000);
    assert_eq!(rpc.balance(probe.escrow), 1_000);
    println!("PASS execution switched to dual runtime, not a stale old-program cache");
    old.finish(retained);
    println!("PASS pre-reload channel and retained signature complete without migration");
    let fresh = Fixture::new(&rpc, 2);
    fresh.partially_use();
    fresh.finish(fresh.voucher(700));
    println!("PASS frozen historical Rust client creates and closes a new V1 on dual runtime");
    println!("PASS binary reload compatibility (NOT a signed loader upgrade)");
}
