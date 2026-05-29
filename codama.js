const IDL_PATH = './program/payment_channels/idl/payment_channels.json';

export default {
  idl: IDL_PATH,
  scripts: {
    idl: [
      './codama-visitors.mjs#addGeneratedClientAccountMetadata',
      {
        from: './codama-visitors.mjs#writeCodamaIdl',
        args: [IDL_PATH],
      },
    ],
    js: {
      from: '@codama/renderers-js',
      args: [
        './clients/typescript',
        {
          formatCode: true,
          syncPackageJson: false,
          // Redirect number-codec imports to our guarded encoders
          // that reject unsafe-integer JS numbers at runtime. The companion
          // narrow-codama-types.mjs script handles the compile-time half.
          dependencyMap: { solanaCodecsNumbers: '../../safe-codecs.js' },
        },
      ],
    },
    rust: {
      from: '@codama/renderers-rust',
      args: ['./clients/rust', { formatCode: true, syncCargoToml: false }],
    },
  },
};
