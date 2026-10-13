// V2 is deliberately opt-in and never overwrites the default V1 artifacts.
export default {
  idl: './program/payment_channels/idl/payment_channels_v2.json',
  scripts: {
    idl: [
      './codama-v2-visitors.mjs#addLifecycleTypes',
      './codama-visitors.mjs#addGeneratedClientAccountMetadata',
      './codama-visitors.mjs#normalizeEvents',
      {
        from: './codama-visitors.mjs#writeCodamaIdl',
        args: ['./program/payment_channels/idl/payment_channels_v2.json'],
      },
    ],
    js: {
      from: '@codama/renderers-js',
      args: ['./clients/typescript-v2', { formatCode: true, syncPackageJson: false }],
    },
    rust: {
      from: '@codama/renderers-rust',
      args: ['./clients/rust-v2', { formatCode: true, syncCargoToml: false }],
    },
  },
};
