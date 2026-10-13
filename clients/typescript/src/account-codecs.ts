import { createDecoder, type FixedSizeDecoder } from '@solana/kit';

/**
 * Validate a complete channel account before decoding it. Embedded channel
 * headers use their own structural codec: a V2 header is not a V1 account.
 */
export function strictChannelDecoder<T>(
  decoder: FixedSizeDecoder<T>,
  version: 1 | 2,
): FixedSizeDecoder<T> {
  return createDecoder({
    fixedSize: decoder.fixedSize,
    read(bytes, offset) {
      if (bytes.length - offset !== decoder.fixedSize) {
        throw new Error(`Channel version ${version} requires exactly ${decoder.fixedSize} bytes`);
      }
      if (bytes[offset] !== 1 || bytes[offset + 1] !== version) {
        throw new Error(`Invalid channel discriminator or version; expected version ${version}`);
      }
      return decoder.read(bytes, offset);
    },
  });
}
