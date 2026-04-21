#!/usr/bin/env node
/**
 * Argus Security — interactive installer
 * Installs security protection for Claude Code CLI, Desktop, and Web.
 *
 * Usage:
 *   npx argus-security           ← interactive
 *   npx argus-security --cli     ← Claude Code CLI only
 *   npx argus-security --desktop ← Claude Desktop only
 *   npx argus-security --web     ← Claude Web only
 *   npx argus-security --all     ← everything
 *   npx argus-security uninstall ← remove all hooks
 *   npx argus-security status    ← check what's installed
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execSync, spawnSync } = require('child_process');
const readline = require('readline');

// ── ANSI colours ──────────────────────────────────────────────────────────────
const c = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  red:    '\x1b[91m',
  green:  '\x1b[92m',
  yellow: '\x1b[93m',
  blue:   '\x1b[94m',
  cyan:   '\x1b[96m',
  white:  '\x1b[97m',
};
const bold   = s => `${c.bold}${s}${c.reset}`;
const green  = s => `${c.green}${s}${c.reset}`;
const yellow = s => `${c.yellow}${s}${c.reset}`;
const red    = s => `${c.red}${s}${c.reset}`;
const cyan   = s => `${c.cyan}${s}${c.reset}`;
const dim    = s => `${c.dim}${s}${c.reset}`;

// ── Paths ─────────────────────────────────────────────────────────────────────
const PKG_DIR   = path.join(__dirname, '..');        // root of this package
const ARGUS_HOME = path.join(os.homedir(), '.argus');
const INSTALL_DIR = path.join(os.homedir(), '.argus', 'lib'); // where we copy files

// Claude settings paths per OS
function claudeCodeSettings() {
  if (process.env.APPDATA)
    return path.join(process.env.APPDATA, 'Claude', 'settings.json');
  return path.join(os.homedir(), '.claude', 'settings.json');
}

function claudeDesktopConfig() {
  if (process.platform === 'darwin')
    return path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  if (process.env.APPDATA)
    return path.join(process.env.APPDATA, 'Claude', 'claude_desktop_config.json');
  return path.join(os.homedir(), '.config', 'Claude', 'claude_desktop_config.json');
}

function skillsDir() {
  if (process.env.APPDATA)
    return path.join(process.env.APPDATA, 'Claude', 'skills', 'argus-scanner');
  return path.join(os.homedir(), '.claude', 'skills', 'argus-scanner');
}

// ── Banner ────────────────────────────────────────────────────────────────────
function banner(version) {
  console.log(`
${cyan(' ▄▄▄  ██████   ██████  ██    ██  ██████ ')}
${cyan('██   ██ ██   ██ ██      ██    ██ ██      ')}
${cyan('███████ ██████  ██  ███ ██    ██  █████  ')}
${cyan('██   ██ ██   ██ ██   ██ ██    ██      ██ ')}
${cyan('██   ██ ██   ██  ██████  ██████  ██████  ')}
${bold('  Security system for Claude')} ${dim(`— v${version}`)}
`);
}

// ── Dependency checks ─────────────────────────────────────────────────────────
function checkDep(cmd) {
  try {
    const r = spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8' });
    if (r.status === 0) return r.stdout.trim().split('\n')[0];
    return null;
  } catch { return null; }
}

function detectEnvironment() {
  const env = {
    python:      checkDep(['python3', '--version']) || checkDep(['python', '--version']),
    jq:          checkDep(['jq', '--version']),
    node:        process.version,
    cliSettings: fs.existsSync(claudeCodeSettings()),
    desktopCfg:  fs.existsSync(path.dirname(claudeDesktopConfig())),
    pip:         checkDep(['pip3', '--version']) || checkDep(['pip', '--version']),
  };
  env.pythonCmd = checkDep(['python3', '--version']) ? 'python3' : 'python';
  return env;
}

function printEnv(env) {
  console.log(bold('Detected:'));
  console.log(`  ${env.cliSettings ? green('✓') : yellow('?')} Claude Code CLI settings ${env.cliSettings ? '' : dim('(not found — will create)')} `);
  console.log(`  ${env.desktopCfg  ? green('✓') : dim('–')} Claude Desktop config dir`);
  console.log(`  ${env.python      ? green('✓') : red('✗')} ${env.python || 'Python not found — required!'}`);
  console.log(`  ${env.jq          ? green('✓') : red('✗')} ${env.jq    || 'jq not found — required!'}`);
  console.log(`  ${green('✓')} Node.js ${env.node}`);
  console.log();
}

// ── File installation ─────────────────────────────────────────────────────────
function copyFiles() {
  const dirs = [
    'hooks', 'mcp-server', 'scripts', 'data',
  ];
  fs.mkdirSync(INSTALL_DIR, { recursive: true });
  fs.mkdirSync(path.join(ARGUS_HOME, 'logs'), { recursive: true });

  for (const dir of dirs) {
    const src  = path.join(PKG_DIR, dir);
    const dest = path.join(INSTALL_DIR, dir);
    if (!fs.existsSync(src)) continue;
    fs.mkdirSync(dest, { recursive: true });
    for (const file of fs.readdirSync(src)) {
      const srcFile  = path.join(src, file);
      const destFile = path.join(dest, file);
      if (fs.statSync(srcFile).isFile()) {
        fs.copyFileSync(srcFile, destFile);
      }
    }
  }

  // Copy skill and web instructions
  for (const file of ['SKILL.md', 'WEB_INSTRUCTIONS.md']) {
    const src = path.join(PKG_DIR, file);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(INSTALL_DIR, file));
  }

  // Make Python scripts executable
  const scripts = [
    path.join(INSTALL_DIR, 'hooks', 'preflight.py'),
    path.join(INSTALL_DIR, 'hooks', 'postcheck.py'),
    path.join(INSTALL_DIR, 'hooks', 'session-report.py'),
    path.join(INSTALL_DIR, 'mcp-server', 'server.py'),
  ];
  for (const s of scripts) {
    if (fs.existsSync(s)) {
      try { fs.chmodSync(s, 0o755); } catch {}
    }
  }
}

// ── Claude Code CLI install ───────────────────────────────────────────────────
function installCLI(pythonCmd) {
  const settingsPath = claudeCodeSettings();
  const preflightPy  = path.join(INSTALL_DIR, 'hooks', 'preflight.py');
  const postcheckPy  = path.join(INSTALL_DIR, 'hooks', 'postcheck.py');
  const stopPy       = path.join(INSTALL_DIR, 'hooks', 'session-report.py');

  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });

  let settings = {};
  if (fs.existsSync(settingsPath)) {
    // Backup
    fs.copyFileSync(settingsPath, `${settingsPath}.argus-backup-${Date.now()}`);
    try { settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8')); } catch {}
  }

  if (!settings.hooks) settings.hooks = {};

  function addHook(section, cmd) {
    if (!settings.hooks[section]) settings.hooks[section] = [];
    const already = settings.hooks[section].some(
      h => h.hooks && h.hooks.some(hh => hh.command === cmd)
    );
    if (!already) {
      settings.hooks[section].push({ matcher: '', hooks: [{ type: 'command', command: cmd }] });
    }
  }

  addHook('PreToolUse',  `${pythonCmd} ${preflightPy}`);
  addHook('PostToolUse', `${pythonCmd} ${postcheckPy}`);
  addHook('Stop',        `${pythonCmd} ${stopPy}`);

  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));

  // Install skill
  const skillDest = skillsDir();
  fs.mkdirSync(skillDest, { recursive: true });
  const skillSrc = path.join(INSTALL_DIR, 'SKILL.md');
  if (fs.existsSync(skillSrc)) fs.copyFileSync(skillSrc, path.join(skillDest, 'SKILL.md'));

  return settingsPath;
}

// ── Claude Desktop install ────────────────────────────────────────────────────
function installDesktop(pythonCmd) {
  const cfgPath   = claudeDesktopConfig();
  const serverPy  = path.join(INSTALL_DIR, 'mcp-server', 'server.py');

  // Install mcp Python SDK if needed
  try {
    spawnSync(pythonCmd, ['-c', 'import mcp'], { encoding: 'utf8' });
  } catch {
    console.log(dim('  Installing mcp Python SDK...'));
    spawnSync('pip3', ['install', 'mcp', '--quiet'], { stdio: 'inherit' });
  }

  fs.mkdirSync(path.dirname(cfgPath), { recursive: true });

  let cfg = {};
  if (fs.existsSync(cfgPath)) {
    fs.copyFileSync(cfgPath, `${cfgPath}.argus-backup-${Date.now()}`);
    try { cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8')); } catch {}
  }

  if (!cfg.mcpServers) cfg.mcpServers = {};
  cfg.mcpServers['argus-security'] = {
    command: pythonCmd,
    args:    [serverPy],
  };

  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
  return cfgPath;
}

// ── Claude Web ────────────────────────────────────────────────────────────────
function installWeb() {
  const webFile = path.join(INSTALL_DIR, 'WEB_INSTRUCTIONS.md');
  if (!fs.existsSync(webFile)) return null;

  const content = fs.readFileSync(webFile, 'utf8');

  // Try to copy to clipboard
  let copied = false;
  try {
    if (process.platform === 'darwin')
      spawnSync('pbcopy', [], { input: content });
    else if (process.platform === 'linux')
      spawnSync('xclip', ['-selection', 'clipboard'], { input: content }) ||
      spawnSync('xsel',  ['--clipboard', '--input'],  { input: content });
    else if (process.platform === 'win32')
      spawnSync('clip', [], { input: content });
    copied = true;
  } catch {}

  return { path: webFile, copied };
}

// ── Uninstall ─────────────────────────────────────────────────────────────────
function uninstall(pythonCmd) {
  // Remove CLI hooks
  const settingsPath = claudeCodeSettings();
  if (fs.existsSync(settingsPath)) {
    let settings = {};
    try { settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8')); } catch {}
    const installDir = INSTALL_DIR;
    for (const section of ['PreToolUse', 'PostToolUse', 'Stop']) {
      if (settings.hooks && settings.hooks[section]) {
        settings.hooks[section] = settings.hooks[section].filter(
          h => !h.hooks || !h.hooks.some(hh => hh.command && hh.command.includes(installDir))
        );
      }
    }
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
    console.log(green('✓') + ' Removed CLI hooks from settings.json');
  }

  // Remove Desktop MCP
  const cfgPath = claudeDesktopConfig();
  if (fs.existsSync(cfgPath)) {
    let cfg = {};
    try { cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8')); } catch {}
    if (cfg.mcpServers && cfg.mcpServers['argus-security']) {
      delete cfg.mcpServers['argus-security'];
      fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
      console.log(green('✓') + ' Removed argus-security from Desktop MCP config');
    }
  }

  // Remove skill
  const sd = skillsDir();
  if (fs.existsSync(sd)) {
    fs.rmSync(sd, { recursive: true, force: true });
    console.log(green('✓') + ' Removed scanner skill');
  }

  // Remove installed files
  if (fs.existsSync(INSTALL_DIR)) {
    fs.rmSync(INSTALL_DIR, { recursive: true, force: true });
    console.log(green('✓') + ' Removed installed files from ~/.argus/lib');
  }

  console.log('\n' + green('Argus uninstalled.'));
}

// ── Status ────────────────────────────────────────────────────────────────────
function status() {
  console.log(bold('\nArgus installation status:\n'));

  const settingsPath = claudeCodeSettings();
  let cliInstalled = false;
  if (fs.existsSync(settingsPath)) {
    try {
      const s = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
      cliInstalled = JSON.stringify(s).includes(INSTALL_DIR);
    } catch {}
  }
  console.log(`  Claude Code CLI:  ${cliInstalled ? green('✓ installed') : dim('not installed')}`);

  const cfgPath = claudeDesktopConfig();
  let desktopInstalled = false;
  if (fs.existsSync(cfgPath)) {
    try {
      const c = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
      desktopInstalled = !!(c.mcpServers && c.mcpServers['argus-security']);
    } catch {}
  }
  console.log(`  Claude Desktop:   ${desktopInstalled ? green('✓ installed') : dim('not installed')}`);

  const skillInstalled = fs.existsSync(path.join(skillsDir(), 'SKILL.md'));
  console.log(`  Scanner skill:    ${skillInstalled ? green('✓ installed') : dim('not installed')}`);

  const auditLog = path.join(ARGUS_HOME, 'logs', 'audit.jsonl');
  if (fs.existsSync(auditLog)) {
    const lines = fs.readFileSync(auditLog, 'utf8').trim().split('\n').filter(Boolean);
    const blocks = lines.filter(l => l.includes('"block"')).length;
    console.log(`\n  Audit log: ${lines.length} events, ${red(blocks + ' blocks')}`);
    console.log(dim(`  Location: ${auditLog}`));
  }
  console.log();
}

// ── Interactive menu ──────────────────────────────────────────────────────────
async function interactiveMenu(env) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(r => rl.question(q, r));

  console.log(bold('What would you like to install?\n'));
  console.log(`  ${cyan('[1]')} Claude Code CLI    — ${green('enforced blocking')} via hooks (PreToolUse + PostToolUse + Stop)`);
  console.log(`  ${cyan('[2]')} Claude Desktop     — MCP server with 4 security tools`);
  console.log(`  ${cyan('[3]')} Claude Web         — copy security policy to clipboard for claude.ai`);
  console.log(`  ${cyan('[4]')} All of the above`);
  console.log(`  ${dim('[0]')} Exit\n`);

  const choice = await ask(bold('Choice: '));
  rl.close();
  return choice.trim();
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  const pkg = JSON.parse(fs.readFileSync(path.join(PKG_DIR, 'package.json'), 'utf8'));
  banner(pkg.version);

  const args = process.argv.slice(2);

  // Special commands
  if (args[0] === 'uninstall') { uninstall(); return; }
  if (args[0] === 'status')    { status();    return; }

  const env = detectEnvironment();
  printEnv(env);

  if (!env.python) {
    console.error(red('✗ Python 3 is required. Install from https://python.org'));
    process.exit(1);
  }
  if (!env.jq) {
    console.error(red('✗ jq is required.'));
    console.error(dim('  macOS:  brew install jq'));
    console.error(dim('  Linux:  sudo apt install jq'));
    console.error(dim('  Windows: https://jqlang.org/download/'));
    process.exit(1);
  }

  // Determine what to install
  let installCli     = args.includes('--cli')     || args.includes('--all');
  let installDsk     = args.includes('--desktop')  || args.includes('--all');
  let installWebFlag = args.includes('--web')      || args.includes('--all');

  if (!installCli && !installDsk && !installWebFlag) {
    const choice = await interactiveMenu(env);
    if (choice === '0' || choice === '') { console.log('Bye.'); return; }
    if (choice === '1' || choice === '4') installCli     = true;
    if (choice === '2' || choice === '4') installDsk     = true;
    if (choice === '3' || choice === '4') installWebFlag = true;
    console.log();
  }

  // Copy all files to ~/.argus/lib/
  process.stdout.write('  Copying files to ~/.argus/lib... ');
  copyFiles();
  console.log(green('✓'));

  const results = [];

  // Install CLI
  if (installCli) {
    process.stdout.write(`  Installing Claude Code CLI hooks... `);
    try {
      const settingsPath = installCLI(env.pythonCmd);
      console.log(green('✓'));
      results.push({ platform: 'Claude Code CLI', ok: true, detail: settingsPath });
    } catch (e) {
      console.log(red('✗'));
      results.push({ platform: 'Claude Code CLI', ok: false, detail: e.message });
    }
  }

  // Install Desktop
  if (installDsk) {
    process.stdout.write(`  Installing Claude Desktop MCP server... `);
    try {
      const cfgPath = installDesktop(env.pythonCmd);
      console.log(green('✓'));
      results.push({ platform: 'Claude Desktop', ok: true, detail: cfgPath });
    } catch (e) {
      console.log(red('✗'));
      results.push({ platform: 'Claude Desktop', ok: false, detail: e.message });
    }
  }

  // Web instructions
  if (installWebFlag) {
    process.stdout.write(`  Preparing Claude Web instructions... `);
    try {
      const r = installWeb();
      if (r && r.copied) {
        console.log(green('✓ copied to clipboard'));
        results.push({ platform: 'Claude Web', ok: true, detail: 'Copied to clipboard' });
      } else if (r) {
        console.log(yellow('✓ see file'));
        results.push({ platform: 'Claude Web', ok: true, detail: r.path });
      }
    } catch (e) {
      console.log(red('✗'));
      results.push({ platform: 'Claude Web', ok: false, detail: e.message });
    }
  }

  // Summary
  console.log(`\n${bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}`);
  console.log(bold('  Installation complete\n'));

  for (const r of results) {
    const icon = r.ok ? green('✓') : red('✗');
    console.log(`  ${icon} ${bold(r.platform)}`);
    console.log(`    ${dim(r.detail)}`);
  }

  console.log();

  if (results.some(r => r.platform === 'Claude Code CLI' && r.ok)) {
    console.log(`  ${cyan('→')} Runtime protection is ${green('active')} — hooks will run automatically`);
    console.log(`  ${cyan('→')} To scan your MCPs: tell Claude ${bold('"scan my MCPs"')}`);
  }
  if (results.some(r => r.platform === 'Claude Desktop' && r.ok)) {
    console.log(`  ${cyan('→')} ${yellow('Restart Claude Desktop')} to activate the MCP server`);
  }
  if (results.some(r => r.platform === 'Claude Web' && r.ok)) {
    const webDetail = results.find(r => r.platform === 'Claude Web').detail;
    const webSource = webDetail === 'Copied to clipboard'
      ? 'instructions are in your clipboard'
      : `open ${bold('WEB_INSTRUCTIONS.md')} and copy the content`;
    console.log(`  ${cyan('→')} Claude Web — ${webSource}`);
    console.log(`     ${dim('1.')} Go to ${bold('claude.ai')} → ${bold('Projects')} → select or create a project`);
    console.log(`     ${dim('2.')} Click ${bold('Edit Instructions')} (top right inside the project)`);
    console.log(`     ${dim('3.')} Paste with ${bold('Cmd+V')} and click ${bold('Save')}`);
    console.log(`     ${dim('ℹ')}  Web policy is best-effort — for guaranteed blocking use Claude Code CLI`);
  }

  console.log(`\n  Audit log: ${dim('~/.argus/logs/audit.jsonl')}`);
  console.log(`  View:      ${dim('npx argus-security status')}`);
  console.log(`  Remove:    ${dim('npx argus-security uninstall')}`);
  console.log(`\n${bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}\n`);
}

main().catch(e => {
  console.error(red('\nInstallation failed: ' + e.message));
  process.exit(1);
});
