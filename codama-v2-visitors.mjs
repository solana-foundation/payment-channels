import { readFileSync } from 'node:fs';
import {
  arrayTypeNode,
  camelCase,
  definedTypeLinkNode,
  definedTypeNode,
  enumStructVariantTypeNode,
  enumTypeNode,
  fixedCountNode,
  numberTypeNode,
  optionTypeNode,
  prefixedCountNode,
  publicKeyTypeNode,
  structFieldTypeNode,
  structTypeNode,
} from '@codama/nodes';

const source = readFileSync(
  new URL('./program/payment_channels/src/hooks.rs', import.meta.url),
  'utf8',
);
const field = (name, type) => structFieldTypeNode({ name, type });
const array = (type, count) => arrayTypeNode(type, fixedCountNode(count));
const u8 = () => numberTypeNode('u8');
const link = (name) => definedTypeLinkNode(name);
const names = ['HookMeta', 'HookDescriptor', 'HookState', 'HookContext'];

// Codama's Rust source reader does not discover the non-derived hook structs.
// Extract only their deliberately simple wire declarations rather than keep a
// second list of context fields. Fail closed on any new Rust type or declaration.
function wireType(rustType) {
  if (/^(u8|u64|i64)$/.test(rustType)) return numberTypeNode(rustType);
  if (rustType === 'Address') return publicKeyTypeNode();
  if (names.includes(rustType)) return link(rustType);
  const match = /^\[(\w+); (\w+)\]$/.exec(rustType);
  if (match) {
    const count = /^\d+$/.test(match[2])
      ? Number(match[2])
      : Number(new RegExp(`pub const ${match[2]}: usize = (\\d+);`).exec(source)?.[1]);
    if (!Number.isSafeInteger(count)) throw new Error(`Unknown array size: ${rustType}`);
    return array(wireType(match[1]), count);
  }
  throw new Error(`Unsupported hook wire type: ${rustType}`);
}

function wireStruct(name) {
  const body = new RegExp(`pub struct ${name} \\{([^}]+)\\}`).exec(source)?.[1];
  if (!body) throw new Error(`Missing ${name}`);
  const fields = body
    .trim()
    .split('\n')
    .map((line) => {
      const match = /^\s*pub (\w+): (.+),$/.exec(line);
      if (!match) throw new Error(`Unsupported declaration in ${name}: ${line}`);
      return field(camelCase(match[1]), wireType(match[2]));
    });
  return definedTypeNode({ name, type: structTypeNode(fields) });
}

export const addLifecycleTypes = {
  visitRoot(root) {
    const program = root.program;
    if (program.publicKey !== 'CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ') {
      throw new Error('V2 generation requires the V2 raw IDL (build with --features idl,v2)');
    }
    // An enum's u8 tag is the account count. Each variant then serializes the
    // static-length-prefixed bytes BEFORE its fixed-size account array. A normal
    // Vec<HookMeta> would put the count in the wrong position on the wire.
    const compactAccounts = definedTypeNode({
      name: 'compactHookAccounts',
      type: enumTypeNode(
        Array.from({ length: 5 }, (_, count) =>
          enumStructVariantTypeNode(
            `accounts${count}`,
            structTypeNode([
              field('staticContext', arrayTypeNode(u8(), prefixedCountNode(u8()))),
              field('accounts', array(link('hookMeta'), count)),
            ]),
          ),
        ),
        { size: u8() },
      ),
    });
    const compactDescriptor = definedTypeNode({
      name: 'compactHookDescriptor',
      type: structTypeNode([
        field('program', publicKeyTypeNode()),
        field('entrypoint', array(u8(), 8)),
        field('accounts', link('compactHookAccounts')),
      ]),
    });
    const config = definedTypeNode({
      name: 'hookConfig',
      type: array(optionTypeNode(link('compactHookDescriptor'), { prefix: u8() }), 4),
    });
    const definedTypes = [
      ...program.definedTypes,
      ...names.map(wireStruct),
      compactAccounts,
      compactDescriptor,
      config,
    ];
    const args = definedTypes.find((type) => type.name === 'openArgs');
    if (!args || args.type.kind !== 'structTypeNode') throw new Error('Missing openArgs');
    args.type.fields.push(field('hookConfig', link('hookConfig')));
    const instructions = program.instructions.map((instruction) => {
      const phases = ['open', 'topUp'].includes(instruction.name)
        ? 'preFund, postFund'
        : ['distribute', 'withdrawPayer'].includes(instruction.name)
          ? 'preDistribute, postDistribute'
          : null;
      if (!phases) return instruction;
      return {
        ...instruction,
        docs: [
          ...(instruction.docs ?? []),
          `V2: append enabled hook tails in ${phases} order, after the fixed head and any recipient ATAs.`,
          'Each tail is target program, readonly nonsigner callback authority, then committed extra accounts with their exact writable flags and no signers.',
          'These variable-privilege tails are not synthesized by the generated builders; the caller must append AccountMeta entries.',
        ],
      };
    });
    return { ...root, program: { ...program, instructions, definedTypes } };
  },
};
