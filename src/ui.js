// ducgo v2 - styled SOC UI kit. Node.js stdlib only.
// Minimal ANSI colors with NO_COLOR support. Used by EVERY command.
export const VERSION = '2.0.0';
export const TAGLINE = 'No one can race me';

export const USE_COLOR = !('NO_COLOR' in process.env);

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  faint: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
};

export function isColor() {
  return USE_COLOR;
}

export function paint(name, s) {
  if (!USE_COLOR) return String(s);
  const code = ANSI[name];
  if (!code) return String(s);
  return code + String(s) + ANSI.reset;
}

export function bold(s) { return paint('bold', s); }
export function faint(s) {
  if (!USE_COLOR) return String(s);
  return ANSI.faint + String(s) + ANSI.reset;
}
// dim() is an alias for faint() - used across all commands for subtle lines.
export function dim(s) { return faint(s); }

export function severityColor(sev) {
  switch (String(sev || '').toLowerCase()) {
    case 'critical': return 'red';
    case 'high': return 'yellow';
    case 'medium': return 'cyan';
    case 'low': return 'gray';
    default: return 'gray';
  }
}

export function severity(s) {
  return paint(severityColor(s), String(s || 'info').toUpperCase().padEnd(8));
}

// ---- status helpers (SOC feel, cohesive) ----
export function ok(msg) { console.log(paint('green', `  [OK] ${msg}`)); }
export function err(msg) { console.error(paint('red', `  [ERR] ${msg}`)); }
export function info(msg) { console.log(paint('cyan', `  [..] ${msg}`)); }
export function warn(msg) { console.log(paint('yellow', `  [!!] ${msg}`)); }

// ---- banner: big DUCGO logo, gradient red->amber; DIM English tagline; version ----
const LOGO = [
  '██████╗ ██╗   ██╗ ██████╗  ██████╗  ██████╗ ',
  '██╔══██╗██║   ██║██╔════╝ ██╔════╝ ██╔═══██╗',
  '██║  ██║██║   ██║██║  ███╗██║  ███╗██║   ██║',
  '██║  ██║██║   ██║██║   ██║██║   ██║██║   ██║',
  '██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝',
  '╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝ ',
];

// 256-color ramp red -> amber (SOC style)
const RAMP = [196, 202, 208, 214, 220, 220];

export function banner() {
  const lines = [];
  if (USE_COLOR) {
    for (let i = 0; i < LOGO.length; i++) {
      const c = RAMP[Math.min(i, RAMP.length - 1)];
      lines.push(`\x1b[38;5;${c}m${LOGO[i]}\x1b[0m`);
    }
  } else {
    for (const l of LOGO) lines.push(l);
  }
  lines.push(faint(TAGLINE));
  lines.push(dim(`ducgo v${VERSION}`));
  return lines.join('\n');
}

export function printBanner() {
  console.log(banner());
}

// ---- box ----
export function box(title, lines) {
  const items = (Array.isArray(lines) ? lines : [String(lines)]).map(String);
  const width = Math.max(String(title).length, ...items.map((s) => s.length));
  const top = '+-' + '-'.repeat(width) + '-+';
  const out = [paint('cyan', top)];
  out.push(paint('cyan', '| ') + bold(String(title).padEnd(width)) + paint('cyan', ' |'));
  out.push(paint('cyan', '+-' + '-'.repeat(width) + '-+'));
  for (const s of items) out.push(paint('cyan', '| ') + s.padEnd(width) + paint('cyan', ' |'));
  out.push(paint('cyan', top));
  return out.join('\n');
}

// ---- table ----
export function table(headers, rows) {
  const h = headers.map(String);
  const r = (Array.isArray(rows) ? rows : []).map((row) => row.map((c) => String(c ?? '')));
  const widths = h.map((x, i) => Math.max(x.length, ...r.map((row) => (row[i] ?? '').length)));
  const pad = (s, i) => s.padEnd(widths[i]);
  const lines = [];
  lines.push(bold(h.map(pad).join('  ')));
  lines.push(dim(widths.map((w) => '-'.repeat(w)).join('  ')));
  for (const row of r) lines.push(row.map((c, i) => pad(c, i)).join('  '));
  return lines.join('\n');
}

// ---- live-event line formatter (used by start + events-tail) ----
export function formatEvent(ev) {
  const t = String(ev.time ?? '');
  const sev = severity(ev.severity);
  const type = String(ev.type ?? '');
  const trap = String(ev.trap ?? '');
  const detail = String(ev.detail ?? '').replace(/\s+/g, ' ').slice(0, 140);
  const ip = String(ev.ip ?? '');
  return `[${t}] ${sev} ${type} ${trap} - ${detail} (${ip})`;
}

export function printEvent(ev) {
  console.log(formatEvent(ev));
}

// ---- progress (simple bar, stdlib only) ----
export function progress(current, total, width = 24) {
  const t = Math.max(1, total);
  const c = Math.max(0, Math.min(current, t));
  const filled = Math.round((c / t) * width);
  const bar = '#'.repeat(filled) + '-'.repeat(width - filled);
  const pct = Math.round((c / t) * 100);
  return `[${bar}] ${pct}% (${c}/${t})`;
}
