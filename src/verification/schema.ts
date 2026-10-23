import { z } from 'zod';

export const MITIGATION_IDS = [
  'memory-limit-unlimited',
  'post-size-limit',
  'upload-progress-disabled',
  'fatal-error-backtraces-off',
  'waf-body-limits',
] as const;

const b64url = z.string().regex(/^[A-Za-z0-9_-]+$/);

export const signatureSchema = z.object({
  alg: z.literal('Ed25519'),
  keyId: z.string().regex(/^[0-9a-f]{64}$/),
  publicKey: b64url,
  value: b64url,
});

export const ownerReportSchema = z
  .object({
    schema: z.literal('php2shell-detector/owner-report'),
    schemaVersion: z.literal(1),
    target: z.object({ origin: z.string().url() }),
    runtime: z.object({
      phpVersion: z.string().regex(/^\d{1,2}\.\d{1,2}\.\d{1,3}([-~+.][\w.+~-]*)?$/, 'expected a full PHP version such as 8.3.36'),
      packageVersion: z.string().max(128).optional(),
      sapi: z.string().max(64).optional(),
    }),
    os: z.object({ name: z.string().max(64), version: z.string().max(64).optional() }).optional(),
    packageSource: z.object({
      type: z.enum(['upstream-source', 'distro-package', 'vendor-image', 'other']),
      name: z.string().max(128).optional(),
    }),
    vendorAdvisoryRef: z
      .string()
      .url()
      .refine((u) => u.startsWith('https://'), 'must be https')
      .optional(),
    patch: z.object({
      status: z.enum(['fixed-upstream', 'vendor-backport-applied', 'not-patched', 'unknown']),
      workersRestarted: z.boolean(),
      mitigations: z.array(z.enum(MITIGATION_IDS)).max(MITIGATION_IDS.length).default([]),
    }),
    verifiedAt: z.string().datetime(),
    provenance: z.object({
      method: z.enum(['cli', 'manual']),
      tool: z.object({ name: z.string().max(64), version: z.string().max(32) }).optional(),
      collectedBy: z.string().max(128).optional(),
      commands: z.array(z.string().max(200)).max(10).optional(),
    }),
    signature: signatureSchema.optional(),
  })
  .strict();

export type OwnerReport = z.infer<typeof ownerReportSchema>;
export type ReportSignature = z.infer<typeof signatureSchema>;
