// SOLA4-2 type regression: 64-bit VoucherArgs fields must be `bigint`,
// not `number | bigint`. Checked by `tsc --noEmit` (vitest skips .test-d.ts).
import { expectTypeOf } from 'vitest';

import type { VoucherArgsArgs } from '../generated/types/voucherArgs.js';

expectTypeOf<VoucherArgsArgs['cumulativeAmount']>().toEqualTypeOf<bigint>();
expectTypeOf<VoucherArgsArgs['expiresAt']>().toEqualTypeOf<bigint>();
