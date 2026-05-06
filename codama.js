const IDL_PATH = './program/payment_channels/idl/payment_channels.json';

export default {
  idl: IDL_PATH,
  scripts: {
    idl: [
      './codama-visitors.mjs#addDistributeRecipientRemainingAccounts',
      {
        from: './codama-visitors.mjs#writeCodamaIdl',
        args: [IDL_PATH],
      },
    ],
    js: {
      from: '@codama/renderers-js',
      args: ['./clients/typescript', { formatCode: true, syncPackageJson: false }],
    },
    rust: {
      from: '@codama/renderers-rust',
      args: ['./clients/rust', { formatCode: true, syncCargoToml: false }],
    },
  },
};
