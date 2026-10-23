import type { NextStep } from '../shared/types';

export interface GuidanceContext {
  distro: boolean;
  proxy: boolean;
  branch: string | null;
  unsupportedBranch: boolean;
  originalOrigin: string;
}

// Commands listed here only read versions and changelogs; none change the server.
export function buildNextSteps(ctx: GuidanceContext): NextStep[] {
  const steps: NextStep[] = [
    {
      id: 'confirm-runtime',
      title: 'Confirm the active PHP runtime with the server administrator or host',
      detail:
        'On the server run `php -v` (CLI), and for the web SAPI check `php-fpm -v` / `php-fpm8.x -v` or `apache2ctl -M | grep php` (mod_php). The CLI and web runtimes can differ. For containers, run `php -v` inside the image that is actually deployed.',
    },
    {
      id: 'verify-patch',
      title: 'Verify upstream or vendor patch status',
      detail: ctx.distro
        ? 'Debian/Ubuntu: `apt changelog php8.x-fpm | grep -i CVE-2026-109618`. RHEL family: `rpm -q --changelog php-fpm | grep -i CVE-2026-109618`. Alpine: check the package version against the Alpine security tracker. A distro package may keep the old PHP version string while carrying the fix.'
        : 'Upstream builds: the version must be at or above the fixed release for its branch (see Related CVEs). Packaged builds: search the package changelog / vendor security tracker for CVE-2026-109618 and CVE-2026-109619.',
    },
    {
      id: 'restart-workers',
      title: 'Check that long-running PHP workers were restarted after updating',
      detail:
        'Updating the package does not replace already-running workers. Restart PHP-FPM / Apache / the container and confirm worker start times are after the update. Upstream advises restarting every worker after any related change.',
    },
    {
      id: 'review-logs',
      title: 'Review logs if earlier exposure is suspected',
      detail:
        'Look for multipart requests followed by memory-limit fatal errors, bursts of HTTP 500, unusually large or malformed PHPSESSID cookies, and unexplained PHP worker restarts (research context: Wiz). Absence of these does not prove no compromise.',
    },
    {
      id: 'apply-fix',
      title: 'Apply the official fix or the vendor’s documented remediation',
      detail: ctx.unsupportedBranch
        ? 'This branch has no upstream release containing the fix. Upgrade to a supported branch (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+) or obtain a vendor-supported build; php.net mentions source-only backports for 7.4/8.0/8.1 but does not list versions.'
        : 'Upgrade to 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or newer on the same branch), or install the vendor package that lists these CVEs as fixed, then redeploy and restart.',
    },
    {
      id: 'waf-not-patch',
      title: 'Treat a WAF or temporary mitigation as risk reduction, not proof of patching',
      detail: ctx.proxy
        ? 'A CDN/WAF was detected in front of this site. Request-size limits and managed rules can reduce exposure but the origin PHP must still be patched.'
        : 'Configuration mitigations (memory_limit=-1 via php_admin_value, small post_max_size, session.upload_progress.enabled=0, fatal_error_backtraces=0 on 8.5) reduce exposure only; upstream states updating is the only complete fix.',
    },
    {
      id: 'owner-report',
      title: 'Upgrade this finding with owner-supplied evidence',
      detail:
        'If you administer the site, generate a report with the companion CLI (`node tools/php2shell-attest.mjs`), sign it, add your key under Owner verification → Trusted keys, and import it. Only a signed report from a key you trust can reach “Patch verified”.',
    },
  ];
  return steps;
}
