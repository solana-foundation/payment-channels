import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import {
  argumentValueNode,
  arrayTypeNode,
  definedTypeLinkNode,
  definedTypeNode,
  instructionRemainingAccountsNode,
  numberTypeNode,
  pdaValueNode,
  prefixedCountNode,
  programIdValueNode,
  structFieldTypeNode,
  structTypeNode,
} from '@codama/nodes';
import { setInstructionAccountDefaultValuesVisitor } from '@codama/visitors';

const IDL_PATH = './program/payment_channels/idl/payment_channels.json';
const OMIT_EMPTY_ARRAY_KEYS = new Set([
  'byteDeltas',
  'extraArguments',
  'remainingAccounts',
  'subInstructions',
]);

export const patchDynamicDistributionIdl = {
  visitRoot(root) {
    const program = expectProgram(root);
    const definedTypes = [...expectArray(program.definedTypes, 'program.definedTypes')];
    [distributionRecipientsType(), openArgsType(), distributeArgsType()].forEach((node) =>
      upsertByName(definedTypes, node),
    );

    let sawOpen = false;
    let sawDistribute = false;
    const instructions = expectArray(program.instructions, 'program.instructions').map((ix) => {
      if (ix.name === 'open') {
        sawOpen = true;
        ensureInstructionArg(ix, 'openArgs');
        return ix;
      }
      if (ix.name === 'distribute') {
        sawDistribute = true;
        ensureInstructionArg(ix, 'distributeArgs');
        return {
          ...ix,
          remainingAccounts: recipientAtaTail(),
        };
      }
      return ix;
    });

    if (!sawOpen) throw new Error('Codama IDL is missing open instruction');
    if (!sawDistribute) throw new Error('Codama IDL is missing distribute instruction');
    return { ...root, program: { ...program, definedTypes, instructions } };
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

// Default `eventAuthority` and `selfProgram` accounts on any ix that lists them.
export const setEventAuthorityAndSelfProgramDefaults = setInstructionAccountDefaultValuesVisitor([
  { account: 'eventAuthority', defaultValue: pdaValueNode('eventAuthority') },
  { account: 'selfProgram', defaultValue: programIdValueNode() },
]);

function ensureInstructionArg(ix, publicName) {
  const matches = expectArray(ix.arguments, `${ix.name}.arguments`).filter(
    (arg) =>
      arg.name === publicName &&
      arg.type?.kind === 'definedTypeLinkNode' &&
      arg.type.name === publicName,
  );
  if (matches.length !== 1) {
    throw new Error(`Codama IDL instruction ${ix.name} expected one ${publicName} argument`);
  }
}

function upsertByName(nodes, node) {
  const index = nodes.findIndex((candidate) => candidate.name === node.name);
  index >= 0 ? (nodes[index] = node) : nodes.push(node);
}

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
  if (idl.kind === 'rootNode' && !('additionalPrograms' in idl)) idl.additionalPrograms = [];
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

const number = (format) => numberTypeNode(format);
const link = (name) => definedTypeLinkNode(name);
const field = (name, type) => structFieldTypeNode({ name, type });
const defined = (name, type) => definedTypeNode({ name, type });
const struct = (fields) => structTypeNode(fields);

const distributionRecipientsType = () =>
  defined(
    'distributionRecipients',
    arrayTypeNode(link('distributionEntry'), prefixedCountNode(number('u32'))),
  );

const openArgsType = () =>
  defined(
    'openArgs',
    struct([
      field('salt', number('u64')),
      field('deposit', number('u64')),
      field('gracePeriod', number('u32')),
      field('recipients', link('distributionRecipients')),
    ]),
  );

const distributeArgsType = () =>
  defined('distributeArgs', struct([field('recipients', link('distributionRecipients'))]));

const recipientAtaTail = () => [
  instructionRemainingAccountsNode(argumentValueNode('recipientTokenAccounts'), {
    isWritable: true,
    isSigner: false,
  }),
];
