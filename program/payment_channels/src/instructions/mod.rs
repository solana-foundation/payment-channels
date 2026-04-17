pub mod distribute;
pub mod emit_event;
pub mod finalize;
pub mod helpers;
pub mod open;
pub mod request_close;
pub mod settle;
pub mod settle_and_finalize;
pub mod top_up;
pub mod withdraw_payee;
pub mod withdraw_payer;

use codama::{CodamaInstructions, CodamaType};
use pinocchio::Address;

#[repr(C)]
#[derive(Debug, Clone, Copy, CodamaType)]
pub struct VoucherArgs {
    pub cumulative_amount: u64,
    pub expires_at: i64,
    pub channel_id: Address,
    pub signer: Address,
    pub signature: [u8; 64],
}

#[derive(Debug, CodamaInstructions)]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum PaymentChannelsInstruction {
    #[codama(account(name = "payer", signer, writable))]
    #[codama(account(name = "payee"))]
    #[codama(account(name = "mint"))]
    #[codama(account(name = "authorized_signer"))]
    #[codama(account(name = "channel", writable))]
    #[codama(account(name = "payer_token_account", writable))]
    #[codama(account(name = "channel_token_account", writable))]
    #[codama(account(name = "token_program"))]
    #[codama(account(name = "system_program", default_value = program("system")))]
    #[codama(account(name = "rent"))]
    Open(#[codama(name = "open_args")] open::OpenArgs) = 0,

    #[codama(account(name = "merchant", signer))]
    #[codama(account(name = "channel", writable))]
    #[codama(account(name = "instructions_sysvar"))]
    Settle(#[codama(name = "settle_args")] settle::SettleArgs) = 1,

    #[codama(account(name = "payer", signer, writable))]
    #[codama(account(name = "channel", writable))]
    #[codama(account(name = "payer_token_account", writable))]
    #[codama(account(name = "channel_token_account", writable))]
    #[codama(account(name = "mint"))]
    #[codama(account(name = "token_program"))]
    TopUp(#[codama(name = "top_up_args")] top_up::TopUpArgs) = 2,

    #[codama(account(name = "merchant", signer))]
    #[codama(account(name = "channel", writable))]
    #[codama(account(name = "instructions_sysvar"))]
    SettleAndFinalize(
        #[codama(name = "settle_and_finalize_args")] settle_and_finalize::SettleAndFinalizeArgs,
    ) = 3,

    #[codama(account(name = "payer", signer))]
    #[codama(account(name = "channel", writable))]
    #[codama(account(name = "clock"))]
    RequestClose = 4,

    #[codama(account(name = "cranker"))]
    #[codama(account(name = "channel", writable))]
    #[codama(account(name = "clock"))]
    Finalize = 5,

    #[codama(account(name = "cranker"))]
    #[codama(account(name = "channel", writable))]
    #[codama(account(name = "channel_token_account", writable))]
    #[codama(account(name = "payer_token_account", writable))]
    #[codama(account(name = "mint"))]
    #[codama(account(name = "token_program"))]
    Distribute(#[codama(name = "distribute_args")] distribute::DistributeArgs) = 6,

    #[codama(account(name = "payer", signer))]
    #[codama(account(name = "channel", writable))]
    #[codama(account(name = "channel_token_account", writable))]
    #[codama(account(name = "payer_token_account", writable))]
    #[codama(account(name = "mint"))]
    #[codama(account(name = "token_program"))]
    #[codama(account(name = "clock"))]
    WithdrawPayer = 7,

    #[codama(account(name = "cranker"))]
    #[codama(account(name = "channel", writable))]
    #[codama(account(name = "channel_token_account", writable))]
    #[codama(account(name = "payee_token_account", writable))]
    #[codama(account(name = "payer_token_account", writable))]
    #[codama(account(name = "payer", writable))]
    #[codama(account(name = "mint"))]
    #[codama(account(name = "token_program"))]
    #[codama(account(name = "clock"))]
    WithdrawPayee = 8,

    #[codama(account(name = "event_authority", signer))]
    EmitEvent = 228,
}
