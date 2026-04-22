export default {
  idl: './program/payment_channels/idl/payment_channels.json',
  before: [
    './codama-visitors.mjs#addEventAuthorityPda',
    './codama-visitors.mjs#setEventAuthorityAndSelfProgramDefaults',
  ],
  scripts: {
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
