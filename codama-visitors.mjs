import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import {
  argumentValueNode,
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
