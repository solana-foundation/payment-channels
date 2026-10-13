//! Offline Surfpool integration, deliberately not a LiteSVM substitute.
//! Only program loading and SOL airdrops use local development RPCs. Minting,
//! custody, authorizations, channels, vouchers and refunds are signed transactions.
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    thread::sleep,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use borsh::BorshDeserialize;
use credit_provider::{Authorization, Ledger, client};
use pinocchio::Address;
use serde_json::{Value, json};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

fn address(key: Pubkey) -> Address {
    Address::new_from_array(key.to_bytes())
}
fn key(address: Address) -> Pubkey {
    Pubkey::new_from_array(*address.as_array())
}
fn id(s: &str) -> Pubkey {
    Pubkey::from_str(s).unwrap()
}
fn ro(key: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}
fn rw(key: Pubkey) -> AccountMeta {
    AccountMeta::new(key, false)
}
fn signer(key: Pubkey, writable: bool) -> AccountMeta {
    if writable {
        AccountMeta::new(key, true)
    } else {
        AccountMeta::new_readonly(key, true)
    }
}
fn channel_program() -> Pubkey {
    key(payment_channels::ID)
}
fn token() -> Pubkey {
    id("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}
fn system() -> Pubkey {
    Pubkey::default()
}
fn ata_program() -> Pubkey {
    id("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}
fn rent() -> Pubkey {
    id("SysvarRent111111111111111111111111111111111")
}
fn instructions() -> Pubkey {
    id("Sysvar1nstructions1111111111111111111111111")
}
fn ata(owner: Pubkey, mint: Pubkey) -> Pubkey {
    key(credit_provider::ata_address(
        &address(owner),
        &address(mint),
    ))
}
fn event_authority() -> Pubkey {
    Pubkey::find_program_address(
        &[payment_channels::event_engine::EVENT_AUTHORITY_SEED],
        &channel_program(),
    )
    .0
}

struct Rpc(String);
impl Rpc {
    fn new() -> Self {
        let endpoint = std::env::var("CREDIT_E2E_RPC")
            .expect("run via scripts/test-credit-provider-surfpool.sh");
        let port = endpoint
            .strip_prefix("http://127.0.0.1:")
            .expect("loopback only");
        assert!(
            port.parse::<u16>().is_ok(),
            "endpoint must contain only loopback host and port"
        );
        Self(endpoint)
    }
    fn request(&self, method: &str, params: Value) -> Result<Value, Value> {
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
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "RPC transport failure: {method}");
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        if let Some(error) = value.get("error") {
            Err(error.clone())
        } else {
            Ok(value["result"].clone())
        }
    }
    fn call(&self, method: &str, params: Value) -> Value {
        self.request(method, params)
            .unwrap_or_else(|e| panic!("{method}: {e}"))
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
    fn slot(&self) -> u64 {
        self.call("getSlot", json!([{"commitment":"confirmed"}]))
            .as_u64()
            .unwrap()
    }
    fn send(
        &self,
        label: &str,
        ixs: &[Instruction],
        payer: &Keypair,
        signers: &[&Keypair],
    ) -> Result<String, Value> {
        let hash = self.call("getLatestBlockhash", json!([{"commitment":"confirmed"}]))["value"]["blockhash"].as_str().unwrap().to_owned();
        let tx = Transaction::new_signed_with_payer(
            ixs,
            Some(&payer.pubkey()),
            signers,
            hash.parse().unwrap(),
        );
        let wire = bincode::serialize(&tx).unwrap();
        assert!(
            wire.len() <= 1232,
            "{label}: oversized transaction {} bytes",
            wire.len()
        );
        let simulation = self.call("simulateTransaction", json!([STANDARD.encode(&wire), {"encoding":"base64","sigVerify":true,"commitment":"confirmed"}]));
        if !simulation["value"]["err"].is_null() {
            eprintln!(
                "{label}: simulation error {}; logs {}",
                simulation["value"]["err"], simulation["value"]["logs"]
            );
        }
        // Submit even expected failures: rollback assertions inspect committed
        // ledger state after a real rejected transaction, not just simulation.
        let signature = self.call("sendTransaction", json!([STANDARD.encode(wire), {"encoding":"base64","skipPreflight":true,"preflightCommitment":"confirmed"}])).as_str().unwrap().to_owned();
        for _ in 0..100 {
            let status = self.call(
                "getSignatureStatuses",
                json!([[signature], {"searchTransactionHistory":true}]),
            )["value"][0]
                .clone();
            if !status.is_null() {
                if !status["err"].is_null() {
                    return Err(status);
                }
                if matches!(
                    status["confirmationStatus"].as_str(),
                    Some("confirmed" | "finalized")
                ) {
                    println!(
                        "PASS {label}: {signature}, {} CU",
                        simulation["value"]["unitsConsumed"]
                    );
                    return Ok(signature);
                }
            }
            sleep(Duration::from_millis(100));
        }
        panic!("{label}: confirmation timed out");
    }
}

fn write_key(path: &Path, pair: &Keypair) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(
        serde_json::to_string(&pair.to_bytes().to_vec())
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
}
fn v3_artifact(variable: &str) -> (PathBuf, Vec<u8>) {
    let path = PathBuf::from(std::env::var_os(variable).expect(variable));
    let bytes = fs::read(&path).unwrap();
    assert!(
        has_executable_text(&bytes),
        "{}: missing executable text (no-entrypoint artifact?)",
        path.display()
    );
    assert_eq!(
        &bytes[..7],
        b"\x7fELF\x02\x01\x01",
        "{}: ELF64",
        path.display()
    );
    assert_eq!(
        u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
        3,
        "{}: requires --arch v3",
        path.display()
    );
    (path, bytes)
}
fn has_executable_text(bytes: &[u8]) -> bool {
    if bytes.len() < 64 {
        return false;
    }
    let u64_at = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let start = u64_at(40) as usize;
    let size = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
    if size < 64
        || start
            .checked_add(size * count)
            .is_none_or(|end| end > bytes.len())
    {
        return false;
    }
    let entry = u64_at(24);
    (0..count).any(|i| {
        let at = start + size * i;
        let flags = u64_at(at + 8);
        let address = u64_at(at + 16);
        let offset = u64_at(at + 24);
        let length = u64_at(at + 32);
        flags & 4 != 0
            && length > 0
            && entry >= address
            && entry - address < length
            && offset
                .checked_add(length)
                .is_some_and(|end| end <= bytes.len() as u64)
    })
}
fn create_account(
    payer: Pubkey,
    account: Pubkey,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) -> Instruction {
    let mut data = 0u32.to_le_bytes().to_vec();
    data.extend(lamports.to_le_bytes());
    data.extend(space.to_le_bytes());
    data.extend(owner.to_bytes());
    Instruction {
        program_id: system(),
        accounts: vec![signer(payer, true), signer(account, true)],
        data,
    }
}
fn create_ata(payer: Pubkey, owner: Pubkey, mint: Pubkey) -> Instruction {
    Instruction {
        program_id: ata_program(),
        accounts: vec![
            signer(payer, true),
            rw(ata(owner, mint)),
            ro(owner),
            ro(mint),
            ro(system()),
            ro(token()),
        ],
        data: vec![1],
    }
}
fn token_ix(op: u8, amount: Option<u64>, accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = vec![op];
    if let Some(amount) = amount {
        data.extend(amount.to_le_bytes());
    }
    Instruction {
        program_id: token(),
        accounts,
        data,
    }
}

struct Fixture<'a> {
    rpc: &'a Rpc,
    provider: Pubkey,
    issuer: &'a Keypair,
    owner: Keypair,
    payee: Keypair,
    mint: Pubkey,
    ledger: Pubkey,
    vault: Pubkey,
    payer_ata: Pubkey,
    payee_ata: Pubkey,
    treasury_ata: Pubkey,
    channel: Pubkey,
    escrow: Pubkey,
    auth: Authorization,
}
impl<'a> Fixture<'a> {
    fn new(rpc: &'a Rpc, provider: Pubkey, issuer: &'a Keypair) -> Self {
        let owner = Keypair::new();
        let payee = Keypair::new();
        let mint = Keypair::new();
        rpc.call(
            "requestAirdrop",
            json!([owner.pubkey().to_string(), 10_000_000_000u64]),
        );
        let ledger = key(credit_provider::ledger_address(
            &address(provider),
            &address(owner.pubkey()),
            &address(mint.pubkey()),
        )
        .0);
        let mut init_mint = vec![20, 0];
        init_mint.extend(owner.pubkey().to_bytes());
        init_mint.push(0);
        let rent = rpc
            .call("getMinimumBalanceForRentExemption", json!([82]))
            .as_u64()
            .unwrap();
        rpc.send(
            "create SPL mint",
            &[
                create_account(owner.pubkey(), mint.pubkey(), rent, 82, token()),
                Instruction {
                    program_id: token(),
                    accounts: vec![rw(mint.pubkey())],
                    data: init_mint,
                },
            ],
            &owner,
            &[&owner, &mint],
        )
        .unwrap();
        let treasury = key(payment_channels::constants::TREASURY_OWNER);
        for who in [owner.pubkey(), ledger, payee.pubkey(), treasury] {
            rpc.send(
                "create associated token account",
                &[create_ata(owner.pubkey(), who, mint.pubkey())],
                &owner,
                &[&owner],
            )
            .unwrap();
        }
        let payer_ata = ata(owner.pubkey(), mint.pubkey());
        rpc.send(
            "mint backing tokens",
            &[token_ix(
                7,
                Some(10_000),
                vec![
                    rw(mint.pubkey()),
                    rw(payer_ata),
                    signer(owner.pubkey(), false),
                ],
            )],
            &owner,
            &[&owner],
        )
        .unwrap();
        // A public PDA must remain initializable after an unsolicited donation.
        let mut transfer = 2u32.to_le_bytes().to_vec();
        transfer.extend(
            rpc.call("getMinimumBalanceForRentExemption", json!([0]))
                .as_u64()
                .unwrap()
                .to_le_bytes(),
        );
        rpc.send(
            "prefund ledger PDA with zero-data rent minimum",
            &[Instruction {
                program_id: system(),
                accounts: vec![signer(owner.pubkey(), true), rw(ledger)],
                data: transfer,
            }],
            &owner,
            &[&owner],
        )
        .unwrap();
        let stranger = Keypair::new();
        let wrong = client::initialize(
            &address(provider),
            &address(owner.pubkey()),
            &address(mint.pubkey()),
            &address(stranger.pubkey()),
        );
        let initialization_snapshot = || {
            [
                ledger,
                mint.pubkey(),
                payer_ata,
                ata(ledger, mint.pubkey()),
                ata(payee.pubkey(), mint.pubkey()),
                ata(treasury, mint.pubkey()),
            ]
            .map(|account| rpc.account(account))
        };
        let before = initialization_snapshot();
        let error = rpc
            .send(
                "reject impostor issuer initialization",
                &[wrong],
                &owner,
                &[&owner, &stranger],
            )
            .expect_err("impostor issuer must fail");
        assert_eq!(
            error["err"],
            json!({"InstructionError":[0,"InvalidAccountData"]})
        );
        assert_eq!(initialization_snapshot(), before);
        let initialize = client::initialize(
            &address(provider),
            &address(owner.pubkey()),
            &address(mint.pubkey()),
            &address(issuer.pubkey()),
        );
        let mut missing_signature = initialize.clone();
        missing_signature.accounts[5].is_signer = false;
        let mut substituted_program_data = initialize.clone();
        substituted_program_data.accounts[4].pubkey = Pubkey::find_program_address(
            &[channel_program().as_ref()],
            &key(credit_provider::LOADER),
        )
        .0;
        for (label, ix, signers) in [
            ("missing issuer signature", missing_signature, vec![&owner]),
            (
                "substituted ProgramData",
                substituted_program_data,
                vec![&owner, issuer],
            ),
        ] {
            let error = rpc.send(label, &[ix], &owner, &signers).expect_err(label);
            assert_eq!(
                error["err"],
                json!({"InstructionError":[0,"InvalidAccountData"]}),
                "{label}"
            );
            assert_eq!(
                initialization_snapshot(),
                before,
                "{label}: balances unchanged"
            );
            println!("PASS {label}: intended error, financial accounts unchanged");
        }
        rpc.send(
            "initialize prefunded ledger with real upgrade authority",
            &[client::initialize(
                &address(provider),
                &address(owner.pubkey()),
                &address(mint.pubkey()),
                &address(issuer.pubkey()),
            )],
            &owner,
            &[&owner, issuer],
        )
        .unwrap();
        let mint = mint.pubkey();
        let payee_ata = ata(payee.pubkey(), mint);
        Self {
            rpc,
            provider,
            issuer,
            owner,
            payee,
            mint,
            ledger,
            vault: ata(ledger, mint),
            payer_ata,
            payee_ata,
            treasury_ata: ata(treasury, mint),
            channel: Pubkey::default(),
            escrow: Pubkey::default(),
            auth: Authorization::default(),
        }
    }
    fn ledger(&self) -> Ledger {
        Ledger::try_from_slice(&self.rpc.data(self.ledger)).unwrap()
    }
    fn balance(&self, account: Pubkey) -> u64 {
        let a = self.rpc.account(account);
        if a.is_null() {
            return 0;
        }
        let data = STANDARD.decode(a["data"][0].as_str().unwrap()).unwrap();
        u64::from_le_bytes(data[64..72].try_into().unwrap())
    }
    fn snapshot(&self) -> Vec<Value> {
        // Fee payer lamports intentionally excluded: failed transactions still pay fees.
        [
            self.ledger,
            self.vault,
            self.payer_ata,
            self.channel,
            self.escrow,
            self.payee_ata,
            self.treasury_ata,
        ]
        .into_iter()
        .map(|k| self.rpc.account(k))
        .collect()
    }
    fn deposit(&self, amount: u64) {
        self.rpc
            .send(
                "deposit real SPL backing",
                &[client::deposit(
                    &address(self.provider),
                    &address(self.owner.pubkey()),
                    &address(self.mint),
                    amount,
                )],
                &self.owner,
                &[&self.owner],
            )
            .unwrap();
        assert_eq!(self.ledger().credits, amount);
        assert_eq!(self.balance(self.vault), amount);
    }
    fn approve(&self, amount: u64) {
        self.rpc
            .send(
                "approve bounded refund delegate",
                &[token_ix(
                    4,
                    Some(amount),
                    vec![
                        rw(self.payer_ata),
                        ro(self.ledger),
                        signer(self.owner.pubkey(), false),
                    ],
                )],
                &self.owner,
                &[&self.owner],
            )
            .unwrap();
    }
    fn revoke(&self) {
        self.rpc
            .send(
                "revoke refund delegate",
                &[token_ix(
                    5,
                    None,
                    vec![rw(self.payer_ata), signer(self.owner.pubkey(), false)],
                )],
                &self.owner,
                &[&self.owner],
            )
            .unwrap();
    }
    fn authorize(&mut self, cap: u64, nonce: u64, salt: u64) {
        self.authorize_for(cap, nonce, salt, 1_000);
    }
    fn authorize_for(&mut self, cap: u64, nonce: u64, salt: u64, slots: u64) {
        self.approve(cap);
        let mut distribution = 1u32.to_le_bytes().to_vec();
        distribution.extend(self.payee.pubkey().to_bytes());
        distribution.extend(10_000u16.to_le_bytes());
        // Match the core DistributionPreimage: count(u32) || recipient || bps.
        let distribution_hash = const_crypto::sha2::Sha256::new()
            .update(&distribution)
            .finalize();
        self.auth = Authorization {
            payee: self.payee.pubkey().to_bytes(),
            authorized_signer: self.owner.pubkey().to_bytes(),
            distribution_hash,
            salt,
            open_slot: self.rpc.slot(),
            cap,
            nonce,
            expires_at_slot: self.rpc.slot() + slots,
        };
        self.channel = key(payment_channels::Channel::find_pda(
            &address(self.owner.pubkey()),
            &address(self.payee.pubkey()),
            &address(self.mint),
            &address(self.owner.pubkey()),
            salt,
            self.auth.open_slot,
        )
        .0);
        self.escrow = ata(self.channel, self.mint);
        self.rpc
            .send(
                "owner + issuer authorize one incarnation",
                &[self.authorize_ix(self.issuer.pubkey(), self.auth)],
                &self.owner,
                &[&self.owner, self.issuer],
            )
            .unwrap();
    }
    fn authorize_ix(&self, issuer: Pubkey, authorization: Authorization) -> Instruction {
        client::authorize(
            &address(self.provider),
            &address(self.owner.pubkey()),
            &address(self.mint),
            &address(issuer),
            authorization,
        )
    }
    fn cancel(&self) -> Instruction {
        client::cancel_unfunded(
            &address(self.provider),
            &address(self.owner.pubkey()),
            &address(self.mint),
            &address(self.issuer.pubkey()),
        )
    }
    fn tail(&self, phase: u8) -> Vec<AccountMeta> {
        client::hook_tail(
            &address(self.provider),
            &address(self.owner.pubkey()),
            &address(self.mint),
            &address(self.channel),
            phase,
        )
    }
    fn open(&self, amount: u64) -> Instruction {
        let mut data = vec![1];
        data.extend(self.auth.salt.to_le_bytes());
        data.extend(amount.to_le_bytes());
        data.extend(3_600u32.to_le_bytes());
        data.extend(self.auth.open_slot.to_le_bytes());
        data.extend(1u32.to_le_bytes());
        data.extend(self.payee.pubkey().to_bytes());
        data.extend(10_000u16.to_le_bytes());
        data.extend(client::hook_config(
            &address(self.provider),
            &address(self.owner.pubkey()),
            &address(self.mint),
        ));
        let mut accounts = vec![
            signer(self.owner.pubkey(), true),
            signer(self.owner.pubkey(), true),
            ro(self.payee.pubkey()),
            ro(self.mint),
            ro(self.owner.pubkey()),
            rw(self.channel),
            rw(self.payer_ata),
            rw(self.escrow),
            ro(token()),
            ro(system()),
            ro(rent()),
            ro(ata_program()),
            ro(event_authority()),
            ro(channel_program()),
        ];
        accounts.extend(self.tail(0));
        Instruction {
            program_id: channel_program(),
            accounts,
            data,
        }
    }
    fn top_up(&self, amount: u64) -> Instruction {
        let mut data = vec![3];
        data.extend(amount.to_le_bytes());
        let mut accounts = vec![
            signer(self.owner.pubkey(), true),
            rw(self.channel),
            rw(self.payer_ata),
            rw(self.escrow),
            ro(self.mint),
            ro(token()),
        ];
        accounts.extend(self.tail(0));
        Instruction {
            program_id: channel_program(),
            accounts,
            data,
        }
    }
    fn distribute(&self) -> Instruction {
        let mut data = vec![7];
        data.extend(1u32.to_le_bytes());
        data.extend(self.payee.pubkey().to_bytes());
        data.extend(10_000u16.to_le_bytes());
        let mut accounts = vec![
            rw(self.channel),
            rw(self.owner.pubkey()),
            rw(self.owner.pubkey()),
            rw(self.escrow),
            rw(self.payer_ata),
            rw(self.payee_ata),
            rw(self.treasury_ata),
            ro(self.mint),
            ro(token()),
            ro(event_authority()),
            ro(channel_program()),
            rw(self.payee_ata),
        ];
        accounts.extend(self.tail(3));
        Instruction {
            program_id: channel_program(),
            accounts,
            data,
        }
    }
    fn withdraw(&self) -> Instruction {
        let mut accounts = vec![
            signer(self.owner.pubkey(), true),
            rw(self.channel),
            rw(self.escrow),
            rw(self.payer_ata),
            ro(self.mint),
            ro(token()),
        ];
        accounts.extend(self.tail(3));
        Instruction {
            program_id: channel_program(),
            accounts,
            data: vec![8],
        }
    }
    fn seal(&self, amount: u64) {
        use payment_channels::{VoucherArgs, state::Transmutable};
        let voucher = VoucherArgs::new(address(self.channel), amount, 0);
        let message = voucher.as_bytes();
        let signature = self.owner.sign_message(message);
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
        data.extend(self.owner.pubkey().to_bytes());
        data.extend(signature.as_ref());
        data.extend(message);
        let verify = Instruction {
            program_id: key(payment_channels::ed25519::PROGRAM_ID),
            accounts: vec![],
            data,
        };
        let seal = Instruction {
            program_id: channel_program(),
            accounts: vec![
                signer(self.payee.pubkey(), false),
                rw(self.channel),
                ro(instructions()),
            ],
            data: vec![4, 1],
        };
        self.rpc
            .send(
                "signed voucher + cooperative seal",
                &[verify, seal],
                &self.owner,
                &[&self.owner, &self.payee],
            )
            .unwrap();
    }
    fn send(&self, label: &str, ix: Instruction) {
        self.rpc
            .send(label, &[ix], &self.owner, &[&self.owner])
            .unwrap();
    }
    fn rejects(&self, label: &str, ix: Instruction, issuer: bool) {
        let before = self.snapshot();
        let signers = if issuer {
            vec![&self.owner, self.issuer]
        } else {
            vec![&self.owner]
        };
        let error = self
            .rpc
            .send(label, &[ix], &self.owner, &signers)
            .expect_err(label);
        assert_eq!(
            error["err"],
            json!({"InstructionError":[0,"InvalidAccountData"]}),
            "{label}: intended error"
        );
        assert_eq!(self.snapshot(), before, "{label}: rollback");
        println!("PASS {label}: rejected, all custody/channel accounts unchanged");
    }
}

fn main() {
    let rpc = Rpc::new();
    let dir = PathBuf::from(std::env::var_os("CREDIT_E2E_RUN_DIR").unwrap());
    let issuer = Keypair::new();
    let provider = Keypair::new();
    let issuer_path = dir.join("issuer.json");
    let provider_path = dir.join("provider.json");
    write_key(&issuer_path, &issuer);
    write_key(&provider_path, &provider);
    let (_, channel_bytes) = v3_artifact("PAYMENT_CHANNELS_V2_SO");
    let (provider_path_so, _) = v3_artifact("CREDIT_PROVIDER_SO");
    // Documented Surfpool 1.5 RPC: program_id, hex ELF, byte offset.
    rpc.call(
        "surfnet_writeProgram",
        json!([channel_program().to_string(), hex::encode(channel_bytes), 0]),
    );
    assert_eq!(rpc.account(channel_program())["executable"], true);
    assert_eq!(
        rpc.account(channel_program())["owner"],
        credit_provider::LOADER.to_string()
    );
    rpc.call(
        "requestAirdrop",
        json!([issuer.pubkey().to_string(), 100_000_000_000u64]),
    );
    let out = Command::new(std::env::var("SOLANA_CLI").unwrap_or_else(|_| "solana".into()))
        .args([
            "program",
            "deploy",
            "--url",
            &rpc.0,
            "--keypair",
            issuer_path.to_str().unwrap(),
            "--upgrade-authority",
            issuer_path.to_str().unwrap(),
            "--program-id",
            provider_path.to_str().unwrap(),
            "--use-rpc",
            "--skip-feature-verify",
            "--commitment",
            "confirmed",
            "--max-sign-attempts",
            "5",
            provider_path_so.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    println!("{}", String::from_utf8_lossy(&out.stdout));
    assert!(
        out.status.success(),
        "local upgradeable deployment failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(rpc.account(provider.pubkey())["executable"], true);
    assert_eq!(
        rpc.account(provider.pubkey())["owner"],
        credit_provider::LOADER.to_string()
    );
    let mut f = Fixture::new(&rpc, provider.pubkey(), &issuer);
    f.deposit(2_000);
    f.authorize(1_500, 1, 1);
    let mut replay = f.auth;
    f.rejects(
        "reject overlapping authorization",
        f.authorize_ix(issuer.pubkey(), replay),
        true,
    );
    let mut bad_open = f.open(1_000);
    // Truncate the configured postDistribute slot to disabled, retaining preFund.
    let config_len = client::hook_config(
        &address(f.provider),
        &address(f.owner.pubkey()),
        &address(f.mint),
    )
    .len();
    let start = bad_open.data.len() - config_len;
    bad_open
        .data
        .truncate(start + 1 + 32 + 8 + 1 + 1 + 4 * 33 + 2);
    bad_open.data.push(0);
    f.rejects(
        "reject changed refund policy before any funding",
        bad_open,
        false,
    );
    f.send("open consumes 1000 backed credits", f.open(1_000));
    assert_eq!(f.ledger().credits, 1_000);
    assert_eq!(f.ledger().funded, 1_000);
    assert_eq!(f.balance(f.vault), 1_000);
    assert_eq!(f.balance(f.escrow), 1_000);
    assert_eq!(f.balance(f.payer_ata), 8_000);
    f.rejects("funded authorization cannot cancel", f.cancel(), true);
    f.rejects("cap overrun rolls back", f.top_up(501), false);
    f.send("topup consumes another 200 credits", f.top_up(200));
    assert_eq!(f.ledger().credits, 800);
    assert_eq!(f.ledger().funded, 1_200);
    assert_eq!(f.balance(f.vault), 800);
    assert_eq!(f.balance(f.escrow), 1_200);
    f.seal(700);
    f.revoke();
    f.rejects(
        "failed refund hook rolls back merchant and payer transfers",
        f.distribute(),
        false,
    );
    f.approve(500);
    f.send(
        "refund 500 tokens back into custody and credits",
        f.distribute(),
    );
    assert_eq!(f.balance(f.payee_ata), 700);
    assert_eq!(f.balance(f.payer_ata), 8_000);
    assert_eq!(f.balance(f.vault), 1_300);
    assert_eq!(f.ledger().credits, 1_300);
    assert_eq!(f.ledger().refunded, 500);
    assert!(!f.ledger().active);
    let before = f.snapshot();
    if let Err(error) = f.rpc.send(
        "duplicate distribute cannot recredit",
        &[f.distribute()],
        &f.owner,
        &[&f.owner],
    ) {
        assert_eq!(
            error["err"],
            json!({"InstructionError":[0,{"Custom":2400}]})
        );
    }
    assert_eq!(f.snapshot(), before, "duplicate distribute cannot recredit");
    f.approve(1_500);
    f.rejects(
        "consumed nonce cannot authorize again",
        f.authorize_ix(issuer.pubkey(), replay),
        true,
    );
    f.authorize(400, 2, 2);
    f.send("open second credit-backed channel", f.open(400));
    f.seal(200);
    f.send("withdraw refund before terminal distribution", f.withdraw());
    assert_eq!(f.ledger().credits, 1_100);
    assert_eq!(f.balance(f.vault), 1_100);
    assert_eq!(f.balance(f.payer_ata), 8_000);
    assert_eq!(f.balance(f.escrow), 200);
    assert_eq!(f.ledger().refunded, 200);
    assert!(f.ledger().active);
    f.revoke();
    f.send(
        "zero-refund terminal succeeds without delegate",
        f.distribute(),
    );
    assert_eq!(f.ledger().credits, 1_100);
    assert_eq!(f.balance(f.vault), 1_100);
    assert_eq!(f.ledger().refunded, 200);
    assert!(!f.ledger().active);
    f.authorize_for(300, 3, 3, 8);
    for _ in 0..100 {
        if rpc.slot() > f.auth.expires_at_slot {
            break;
        }
        sleep(Duration::from_millis(100));
    }
    assert!(rpc.slot() > f.auth.expires_at_slot, "authorization expired");
    f.rejects("expired authorization cannot fund", f.open(100), false);
    replay = f.auth;
    rpc.send(
        "cancel expired never-funded authorization",
        &[f.cancel()],
        &f.owner,
        &[&f.owner, &issuer],
    )
    .unwrap();
    f.rejects("canceled authorization cannot fund", f.open(100), false);
    f.rejects(
        "canceled nonce cannot replay",
        f.authorize_ix(issuer.pubkey(), replay),
        true,
    );
    f.authorize(300, 4, 4);
    f.send("fresh nonce after cancellation can fund", f.open(100));
    assert_eq!(f.ledger().credits, 1_000);
    assert_eq!(f.balance(f.vault), 1_000);
    println!("PASS offline Surfpool backed-credit end-to-end scenarios");
}

#[cfg(test)]
mod tests {
    use super::has_executable_text;

    #[test]
    fn rejects_no_entrypoint_and_truncated_elf() {
        assert!(!has_executable_text(&[]));
        let mut elf = vec![0; 136];
        elf[40..48].copy_from_slice(&64u64.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf[60..62].copy_from_slice(&1u16.to_le_bytes());
        elf[88..96].copy_from_slice(&128u64.to_le_bytes());
        elf[96..104].copy_from_slice(&8u64.to_le_bytes());
        // A no-entrypoint dependency can contain rodata but no executable section.
        elf[72..80].copy_from_slice(&2u64.to_le_bytes());
        assert!(!has_executable_text(&elf));
        elf[72..80].copy_from_slice(&6u64.to_le_bytes());
        assert!(has_executable_text(&elf));
        assert!(!has_executable_text(&elf[..128]));
    }
}
