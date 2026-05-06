import { constantPdaSeedNodeFromString } from '@codama/nodes';

const IDL_PATH = './program/payment_channels/idl/payment_channels.json';
const EVENT_AUTHORITY_PDA = {
  name: 'eventAuthority',
  seeds: [constantPdaSeedNodeFromString('utf8', 'event_authority')],
};

export default {
  idl: IDL_PATH,
  scripts: {
    idl: [
      './codama-visitors.mjs#patchDynamicDistributionIdl',
      {
        from: '@codama/visitors#addPdasVisitor',
        args: [{ paymentChannels: [EVENT_AUTHORITY_PDA] }],
      },
      './codama-visitors.mjs#setEventAuthorityAndSelfProgramDefaults',
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
