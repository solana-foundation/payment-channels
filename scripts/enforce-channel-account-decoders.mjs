// Codama's structural codecs accept trailing bytes and do not validate the
// runtime version. Harden only complete channel account entry points. Keep
// the embedded ChannelHeader and BorshDeserialize structural for V2 nesting.
import { readFileSync, writeFileSync } from 'node:fs';

function replaceOnce(source, before, after, file) {
  if (source.split(before).length !== 2) {
    throw new Error(`${file}: expected exactly one decoder template match: ${before}`);
  }
  return source.replace(before, after);
}

for (const [name, snake, version, size] of [
  ['Channel', 'channel', 1, 256],
  ['ChannelWithHooks', 'channel_with_hooks', 2, 1121],
]) {
  const camel = name[0].toLowerCase() + name.slice(1);
  const ts = new URL(`../clients/typescript/src/generated/accounts/${camel}.ts`, import.meta.url);
  let source = readFileSync(ts, 'utf8');
  const start = `export function get${name}Decoder(): FixedSizeDecoder<${name}> {\n  return getStructDecoder([`;
  source = replaceOnce(
    source,
    start,
    `export function get${name}Decoder(): FixedSizeDecoder<${name}> {\n  return strictChannelDecoder(getStructDecoder([`,
    ts,
  );
  const decoderStart = source.indexOf(`export function get${name}Decoder()`);
  const end = source.indexOf('\n  ]);', decoderStart);
  if (end < 0) throw new Error(`${ts}: missing decoder end`);
  source = source.slice(0, end) + `\n  ]), ${version});` + source.slice(end + '\n  ]);'.length);
  source = `import { strictChannelDecoder } from "../../account-codecs.js";\n${source}`;
  writeFileSync(ts, source);

  const rust = new URL(`../clients/rust/src/generated/accounts/${snake}.rs`, import.meta.url);
  source = readFileSync(rust, 'utf8');
  source = replaceOnce(
    source,
    '        let mut data = data;\n        Self::deserialize(&mut data)',
    `        if data.len() != ${size} || data[0] != 1 || data[1] != ${version} {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid channel account size, discriminator, or version",
            ));
        }
        Self::try_from_slice(data)`,
    rust,
  );
  source = replaceOnce(
    source,
    '        let mut data: &[u8] = &(*account_info.data).borrow();\n        Self::deserialize(&mut data)',
    '        Self::from_bytes(&account_info.data.borrow())',
    rust,
  );
  source = replaceOnce(
    source,
    '        Ok(Self::deserialize(buf)?)',
    '        Ok(Self::from_bytes(buf)?)',
    rust,
  );
  writeFileSync(rust, source);
}
