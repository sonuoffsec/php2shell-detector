import { z } from 'zod';

const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}(T[\d:.]+Z)?$/, 'expected ISO-8601 date');
const httpsUrl = z.string().url().refine((u) => u.startsWith('https://'), 'references must be https');
const cveId = z.string().regex(/^CVE-\d{4}-\d{4,}$/);
const branch = z.string().regex(/^\d+\.\d+$/);
const version = z.string().regex(/^\d+\.\d+\.\d+$/);

export const referenceSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  url: httpsUrl,
  publisher: z.string().min(1),
  type: z.enum(['vendor-advisory', 'ghsa', 'research', 'cloud-guidance', 'release-archive']),
  checkedAt: isoDate,
  claims: z.array(z.string().min(1)).min(1),
});

export const advisorySchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1),
    cves: z.array(z.object({ id: cveId, ghsa: z.string().optional(), summary: z.string().min(1) })).min(1),
    cvssV4: z.number().min(0).max(10),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
    published: isoDate,
    updated: isoDate,
    scope: z.object({
      supportedBranches: z.array(z.object({ branch, fixedIn: version })).min(1),
      earliestAffectedBranch: branch,
      endOfLifeBranchesBelow: branch,
      notes: z.array(z.string()),
    }),
    vendorBackports: z.object({
      possible: z.boolean(),
      guidance: z.string().min(1),
      knownVendorAdvisories: z.array(z.object({ vendor: z.string(), url: httpsUrl, checkedAt: isoDate })),
    }),
    mitigations: z.array(
      z.object({
        id: z.string().min(1),
        title: z.string().min(1),
        detail: z.string().min(1),
        completeFix: z.literal(false),
        sourceRefs: z.array(z.string()).min(1),
      }),
    ),
    knownDiscrepancies: z.array(z.string()),
    limitations: z.array(z.string()).min(1),
    referenceIds: z.array(z.string()).min(1),
  })
  .superRefine((a, ctx) => {
    for (const [i, b] of a.scope.supportedBranches.entries()) {
      if (!b.fixedIn.startsWith(`${b.branch}.`)) {
        ctx.addIssue({ code: 'custom', path: ['scope', 'supportedBranches', i, 'fixedIn'], message: `fixedIn ${b.fixedIn} is not on branch ${b.branch}` });
      }
    }
  });

export const advisoryDatasetSchema = z
  .object({
    schemaVersion: z.literal(1),
    dataset: z.object({
      id: z.string(),
      lastVerifiedAt: isoDate,
      maxAgeDays: z.number().int().positive(),
      maintainerNote: z.string(),
    }),
    references: z.array(referenceSchema).min(1),
    advisories: z.array(advisorySchema).min(1),
  })
  .superRefine((d, ctx) => {
    const ids = new Set(d.references.map((r) => r.id));
    for (const [i, a] of d.advisories.entries()) {
      for (const r of a.referenceIds) {
        if (!ids.has(r)) ctx.addIssue({ code: 'custom', path: ['advisories', i, 'referenceIds'], message: `unknown reference ${r}` });
      }
      for (const m of a.mitigations) {
        for (const r of m.sourceRefs) {
          if (!ids.has(r)) ctx.addIssue({ code: 'custom', path: ['advisories', i, 'mitigations'], message: `unknown reference ${r}` });
        }
      }
    }
  });

export type AdvisoryDataset = z.infer<typeof advisoryDatasetSchema>;
export type Advisory = AdvisoryDataset['advisories'][number];
