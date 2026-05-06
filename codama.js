export default {
  idl: './program/payment_channels/idl/payment_channels.json',
  before: [
    './codama-visitors.mjs#patchDynamicDistributionIdl',
    './codama-visitors.mjs#addEventAuthorityPda',
    './codama-visitors.mjs#setEventAuthorityAndSelfProgramDefaults',
  ],
  scripts: {
    idl: {
      from: './codama-visitors.mjs#writeCodamaIdl',
      args: ['./program/payment_channels/idl/payment_channels.json'],
    },
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
