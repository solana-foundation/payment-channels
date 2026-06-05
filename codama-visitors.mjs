import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import {
  argumentValueNode,
  bytesTypeNode,
  bytesValueNode,
  constantDiscriminatorNode,
  constantValueNode,
  definedTypeNode,
  eventNode,
  fixedSizeTypeNode,
  hiddenPrefixTypeNode,
  instructionRemainingAccountsNode,
  publicKeyValueNode,
} from '@codama/nodes';

const IDL_PATH = './program/payment_channels/idl/payment_channels.json';
const CODAMA_STANDARD_VERSION = '1.6.0';
const OMIT_EMPTY_ARRAY_KEYS = new Set([
  'byteDeltas',
  'extraArguments',
  'remainingAccounts',
  'subInstructions',
]);

// Codama's Rust macros define the wire schema and fixed instruction accounts.
// Keep this visitor scoped to generated-client account metadata that is either
// not exposed by Rust macros or would duplicate the declared program id in Rust.
export const addGeneratedClientAccountMetadata = {
  visitRoot(root) {
    const program = expectProgram(root);
    let sawDistribute = false;
    let sawSelfProgram = false;
    const instructions = expectArray(program.instructions, 'program.instructions').map((ix) => {
      const accounts = expectArray(ix.accounts, `instruction ${ix.name}.accounts`).map(
        (account) => {
          if (account.name !== 'selfProgram') return account;
          sawSelfProgram = true;
          return {
            ...account,
            defaultValue: publicKeyValueNode(program.publicKey),
          };
        },
      );

      if (ix.name !== 'distribute') return { ...ix, accounts };
      sawDistribute = true;
      return {
        ...ix,
        accounts,
        remainingAccounts: recipientAtaTail(),
      };
    });

    if (!sawDistribute) throw new Error('Codama IDL is missing distribute instruction');
    if (!sawSelfProgram) throw new Error('Codama IDL is missing selfProgram account');
    return { ...root, program: { ...program, instructions } };
  },
};

// The Rust `CodamaEvent` derive emits eventNodes with a plain struct as data
// and moves the type out of definedTypes. Neither codama renderer consumes
// eventNodes, so left alone the generated client types for events would
// disappear. This visitor reshapes each event to the @codama/nodes-from-anchor
// convention (the discriminator as an 8-byte hidden prefix on the data, plus a
// constantDiscriminatorNode at offset 0) so IDL-driven consumers decode our
// events like any Anchor program's, and mirrors the bare struct back into
// definedTypes so the renderers keep emitting the same client types, byte for
// byte. The mirror must use the bare struct and not the hidden-prefix wrapper,
// otherwise the discriminator gets baked into the type codecs and silently
// breaks the wire format.
export const normalizeEvents = {
  visitRoot(root) {
    const program = expectProgram(root);
    const eventNodes = expectArray(program.events, 'program.events');
    if (eventNodes.length === 0) {
      throw new Error(
        'Codama IDL has no events, expected CodamaEvent derives on Opened/PayoutRedirected',
      );
    }
    const definedTypes = [...expectArray(program.definedTypes, 'program.definedTypes')];

    const events = eventNodes.map((event) => {
      const data = bareEventStruct(event);
      const discriminator = singleConstantDiscriminator(event);

      if (definedTypes.some((type) => type.name === event.name)) {
        throw new Error(`Codama IDL event ${event.name} collides with an existing defined type`);
      }
      // Cloned so the mirror and the event wrapper don't share one struct node.
      definedTypes.push(definedTypeNode({ name: event.name, type: { ...data } }));

      const constant = constantValueNode(
        fixedSizeTypeNode(bytesTypeNode(), 8),
        bytesValueNode('base16', discriminator),
      );
      return eventNode({
        name: event.name,
        data: hiddenPrefixTypeNode({ ...data }, [constant]),
        discriminators: [constantDiscriminatorNode(constant)],
      });
    });

    return { ...root, program: { ...program, events, definedTypes } };
  },
};

// The event's bare struct, whether or not the data was already wrapped
// (keeps the visitor idempotent if codama ever pre-wraps).
function bareEventStruct(event) {
  const data = event.data?.kind === 'hiddenPrefixTypeNode' ? event.data.type : event.data;
  if (data?.kind !== 'structTypeNode') {
    throw new Error(`Codama IDL event ${event.name}: expected struct data, got ${data?.kind}`);
  }
  return data;
}

function singleConstantDiscriminator(event) {
  const discriminators = expectArray(event.discriminators, `event ${event.name}.discriminators`);
  if (discriminators.length !== 1) {
    throw new Error(`Codama IDL event ${event.name}: expected exactly one discriminator`);
  }
  const value = discriminators[0]?.constant?.value;
  if (
    discriminators[0].kind !== 'constantDiscriminatorNode' ||
    discriminators[0].offset !== 0 ||
    value?.kind !== 'bytesValueNode' ||
    value.encoding !== 'base16' ||
    value.data.length !== 16
  ) {
    throw new Error(
      `Codama IDL event ${event.name}: expected an 8-byte base16 constant discriminator at offset 0`,
    );
  }
  return value.data;
}

export const writeCodamaIdl = (outputPath = IDL_PATH) => ({
  visitRoot(root) {
    const out = resolve(process.cwd(), outputPath);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${stringifyCodamaIdl(root)}\n`);
    return root;
  },
});

function expectProgram(root) {
  if (root?.kind !== 'rootNode' || root.program?.kind !== 'programNode') {
    throw new Error('Codama root is missing program node');
  }
  return root.program;
}

function expectArray(value, path) {
  if (!Array.isArray(value)) throw new Error(`Codama IDL expected ${path} to be an array`);
  return value;
}

function stringifyCodamaIdl(root) {
  const idl = prune(root);
  if (idl.kind === 'rootNode') {
    idl.version = CODAMA_STANDARD_VERSION;
    if (!('additionalPrograms' in idl)) idl.additionalPrograms = [];
  }
  return JSON.stringify(sortKeys(idl), null, 2);
}

function prune(value) {
  if (Array.isArray(value)) return value.map(prune);
  if (!value || typeof value !== 'object') return value;

  const out = {};
  for (const [key, child] of Object.entries(value)) {
    if (key === 'docs' && Array.isArray(child) && child.length === 0) continue;
    if (key === 'isOptional' && child === false) continue;
    if (key === 'optionalAccountStrategy' && child === 'programId') continue;
    if (OMIT_EMPTY_ARRAY_KEYS.has(key) && Array.isArray(child) && child.length === 0) continue;
    if (key === 'status' && child == null) continue;
    out[key] = prune(child);
  }
  return out;
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => [key, sortKeys(child)]),
  );
}

const recipientAtaTail = () => [
  instructionRemainingAccountsNode(argumentValueNode('recipientTokenAccounts'), {
    isWritable: true,
    isSigner: false,
  }),
];
