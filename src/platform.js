// ducgo v3.0.4 - cross-platform helpers (stdlib only, zero runtime deps).
// Single place that maps Node's os.platform() to the three supported
// families and exposes per-OS paths + privilege probes.
//
// Families: 'windows' | 'linux' | 'darwin'.
// Any other Node platform string (freebsd, openbsd, sunos, ...) maps to
// 'linux' so POSIX backends (ss / ip / tcpdump) are attempted with clean
// "not available" guidance instead of crashing.
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

export const HIGH_INTEGRITY_SID = 'S-1-16-12288';

// Map a Node os.platform() string to a ducgo family. The platform string is
// a parameter (dependency injection) so unit tests pass 'win32' / 'linux' /
// 'darwin' directly - never monkey-patch the global os module.
export function platform(osName = os.platform()) {
  const s = String(osName || '').toLowerCase();
  if (s === 'win32' || s === 'windows') return 'windows';
  if (s === 'darwin') return 'darwin';
  return 'linux';
}

// Privilege probe. Windows: high-integrity SID in `whoami /groups`.
// POSIX: `id -u` == 0 (root). Optional `run` injection is (cmd, args) =>
// { status, stdout } for unit tests. Returns boolean, never throws.
export function isAdmin(plat = platform(), run = null) {
  try {
    if (plat === 'windows') {
      const r = run
        ? run('whoami', ['/groups'])
        : spawnSync('whoami', ['/groups'], { encoding: 'utf8', timeout: 8000, windowsHide: true });
      return !!r && r.status === 0 && String(r.stdout || '').includes(HIGH_INTEGRITY_SID);
    }
    const r = run
      ? run('id', ['-u'])
      : spawnSync('id', ['-u'], { encoding: 'utf8', timeout: 8000, windowsHide: true });
    return !!r && r.status === 0 && String(r.stdout || '').trim() === '0';
  } catch {
    return false;
  }
}

// Per-OS hosts file path. Linux and macOS both serve /etc/hosts
// (on macOS it symlinks to /private/etc/hosts).
export function hostsPath(plat = platform()) {
  if (plat === 'windows') {
    const root = process.env.SystemRoot || process.env.windir || 'C:\\Windows';
    return path.join(root, 'System32', 'drivers', 'etc', 'hosts');
  }
  return '/etc/hosts';
}

// Tool data-dir default (no env override here - callers layer MIRAGENET_DIR
// on top). Always os.homedir()-based: ~/.miragenet on every OS.
export function dataDir() {
  return path.join(os.homedir(), '.miragenet');
}

// Probe PATH for a command. Windows: `where <cmd>`; POSIX: `command -v`
// via sh (command is a shell builtin, not a binary). Returns boolean,
// never throws. Names with shell metacharacters are rejected (false).
export function hasCmd(cmd, plat = platform()) {
  const c = String(cmd || '').trim();
  if (!c || /[\s;&|<>$`"'\\*?~#(){}!]/.test(c)) return false;
  try {
    if (plat === 'windows') {
      const r = spawnSync('where', [c], { encoding: 'utf8', timeout: 5000, windowsHide: true });
      return !!r && r.status === 0;
    }
    const r = spawnSync('sh', ['-c', `command -v '${c}'`], { encoding: 'utf8', timeout: 5000, windowsHide: true });
    return !!r && r.status === 0 && String(r.stdout || '').trim() !== '';
  } catch {
    return false;
  }
}
