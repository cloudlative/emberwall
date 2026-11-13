// Shell completion for the emberwall CLI: `emberwall completion bash|zsh|fish` prints a script.
// The word lists (commands, flags, targets, profiles) are written into the script, so pressing Tab
// never starts the CLI, and they come from the same data the CLI validates against.
import { PROFILES } from '../src/core/compliance';
import { DISTROS, TOOLS, VERSIONS } from '../src/core/targets';

export const SHELLS = ['bash', 'zsh', 'fish'] as const;
export type Shell = (typeof SHELLS)[number];

type Value = 'target' | 'profile' | 'dir' | 'number';
interface Flag { name: string; about: string; value?: Value }
interface Command { name: string; about: string; project?: boolean; flags: Flag[] }

const out: Flag = { name: 'out', about: 'Write the files to this folder', value: 'dir' };

/** Every command and its flags. Keep in step with HELP in cli/emberwall.ts (a test checks). */
export const COMMANDS: Command[] = [
  { name: 'build', about: 'Compile a project for one target', project: true, flags: [
    { name: 'target', about: 'distro:tool or tool@version', value: 'target' },
    out,
    { name: 'iac', about: 'Also write Ansible, Terraform and cloud-init files' },
    { name: 'strict', about: 'Fail on version fallbacks or unsupported features' },
  ] },
  { name: 'fleet', about: 'Build every host of a fleet project', project: true, flags: [out] },
  { name: 'audit', about: 'Score a project and list findings', project: true, flags: [{ name: 'min-score', about: 'Fail below this score (0-100)', value: 'number' }] },
  { name: 'test', about: 'Run the project\'s policy tests', project: true, flags: [] },
  { name: 'compliance', about: 'Check a project against a profile', project: true, flags: [
    { name: 'profile', about: 'Compliance profile', value: 'profile' },
    { name: 'min', about: 'Fail below this percentage (0-100)', value: 'number' },
  ] },
  { name: 'targets', about: 'List distributions, tools and versions', flags: [] },
  { name: 'serve', about: 'Start server mode (standalone binary)', flags: [] },
  { name: 'licenses', about: 'Third-party license notices (standalone binary)', flags: [] },
  { name: 'completion', about: 'Print a shell completion script', flags: [] },
  { name: 'help', about: 'Show help', flags: [] },
  { name: 'version', about: 'Print the version', flags: [] },
];

/** Every value --target accepts: distro, distro:tool and tool@version. */
export function targetWords(): string[] {
  const words: string[] = [];
  for (const d of DISTROS) words.push(d.id, ...Object.keys(d.tools).map((t) => `${d.id}:${t}`));
  for (const t of TOOLS) words.push(...VERSIONS[t].map((v) => `${t}@${v}`));
  return words;
}

const profiles = () => PROFILES.map((p) => ({ id: p.id, about: p.name }));
/** Single-quote for sh, bash, zsh and fish. */
const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
const fq = (s: string) => `'${s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;

function bash(): string {
  const valued = (v: Value) => COMMANDS.flatMap((c) => c.flags).filter((f) => f.value === v).map((f) => `--${f.name}`);
  const uniq = (xs: string[]) => [...new Set(xs)].join('|');
  return `# emberwall completion for bash. Load it with:  source <(emberwall completion bash)
# or save it as ~/.local/share/bash-completion/completions/emberwall
_emberwall() {
  local IFS=$' \\t\\n' line="\${COMP_LINE:0:COMP_POINT}" cur prev cmd n
  local -a words
  read -ra words <<< "$line"
  n=\${#words[@]}
  if [[ -z "$line" || "$line" == *[[:space:]] ]]; then cur=""; else cur="\${words[n-1]}"; n=$((n - 1)); fi
  prev="\${words[n-1]}"
  cmd="\${words[1]}"
  COMPREPLY=()

  if (( n <= 1 )); then _emberwall_words "$cur" ${q(COMMANDS.map((c) => c.name).join(' ') + ' --help --version')}; return; fi
  case "$prev" in
    ${uniq(valued('target'))}) _emberwall_words "$cur" ${q(targetWords().join(' '))}; return ;;
    ${uniq(valued('profile'))}) _emberwall_words "$cur" ${q(profiles().map((p) => p.id).join(' '))}; return ;;
    ${uniq(valued('dir'))}) compopt -o filenames 2>/dev/null; IFS=$'\\n'; COMPREPLY=($(compgen -d -- "$cur")); return ;;
    ${uniq(valued('number'))}) return ;;
  esac

  local flags
  case "$cmd" in
${COMMANDS.filter((c) => c.project).map((c) => `    ${c.name}) flags=${q(c.flags.map((f) => `--${f.name}`).join(' '))} ;;`).join('\n')}
    completion) (( n == 2 )) && _emberwall_words "$cur" ${q(SHELLS.join(' '))}; return ;;
    *) return ;;
  esac
  if [[ "$cur" == -* ]]; then
    local f used=" \${words[*]} " left=""
    for f in $flags; do [[ "$used" == *" $f "* ]] || left="$left $f"; done
    _emberwall_words "$cur" "$left"
  else
    compopt -o filenames 2>/dev/null
    IFS=$'\\n'
    COMPREPLY=($(compgen -f -X '!*.json' -- "$cur") $(compgen -d -- "$cur"))
  fi
}

# compgen -W, then undo bash splitting words at ":" (as in debian-12:nftables).
_emberwall_words() {
  local cur="$1" i pre
  COMPREPLY=($(compgen -W "$2" -- "$cur"))
  if [[ "$cur" == *:* && "$COMP_WORDBREAKS" == *:* ]]; then
    pre="\${cur%"\${cur##*:}"}"
    for i in "\${!COMPREPLY[@]}"; do COMPREPLY[i]="\${COMPREPLY[i]#"$pre"}"; done
  fi
}

complete -F _emberwall emberwall
`;
}

function zsh(): string {
  const esc = (s: string) => s.replace(/:/g, '\\:');
  const flagSpec = (f: Flag) => {
    const action = f.value === 'target' ? ':target:_emberwall_targets' : f.value === 'profile' ? ':profile:_emberwall_profiles' : f.value === 'dir' ? ':folder:_files -/' : f.value === 'number' ? ':number: ' : '';
    return q(`--${f.name}[${f.about.replace(/[[\]]/g, '').replace(/:/g, '\\:')}]${action}`);
  };
  return `#compdef emberwall
# emberwall completion for zsh. Load it with:  source <(emberwall completion zsh)   (after compinit)
# or save it as _emberwall in a folder on $fpath.
_emberwall_targets() {
  local -a t
  t=(${targetWords().map(q).join(' ')})
  compadd -a t
}

_emberwall_profiles() {
  local -a p
  p=(${profiles().map((p) => q(`${esc(p.id)}:${p.about}`)).join(' ')})
  _describe -t profiles 'compliance profile' p
}

_emberwall() {
  local -a commands
  commands=(${COMMANDS.map((c) => q(`${esc(c.name)}:${c.about}`)).join(' ')})
  if (( CURRENT == 2 )); then
    _describe -t commands 'emberwall command' commands
    _arguments '--help[Show help]' '--version[Print the version]'
    return
  fi
  local cmd="$words[2]"
  shift words
  (( CURRENT-- ))
  case "$cmd" in
${COMMANDS.filter((c) => c.project).map((c) => `    ${c.name}) _arguments ${["'1:project file:_files -g \"*.json(-.)\"'", ...c.flags.map(flagSpec)].join(' ')} ;;`).join('\n')}
    completion) _arguments ${q(`1:shell:(${SHELLS.join(' ')})`)} ;;
  esac
}

if [[ "$funcstack[1]" == "_emberwall" ]]; then
  _emberwall "$@"
else
  compdef _emberwall emberwall
fi
`;
}

function fish(): string {
  const lines = [
    '# emberwall completion for fish. Load it with:  emberwall completion fish | source',
    '# or save it as ~/.config/fish/completions/emberwall.fish',
    'complete -c emberwall -f',
    ...COMMANDS.map((c) => `complete -c emberwall -n __fish_use_subcommand -a ${c.name} -d ${fq(c.about)}`),
    `complete -c emberwall -n __fish_use_subcommand -l help -d 'Show help'`,
    `complete -c emberwall -n __fish_use_subcommand -l version -d 'Print the version'`,
    '# Project files: only .json files, and folders to look into.',
    'function __emberwall_projects',
    '    set -l t (commandline -ct)',
    '    for f in $t*.json $t*/',
    '        echo $f',
    '    end',
    'end',
    `complete -c emberwall -n '__fish_seen_subcommand_from ${COMMANDS.filter((c) => c.project).map((c) => c.name).join(' ')}; and not string match -q -- "-*" (commandline -ct)' -a '(__emberwall_projects)'`,
    `complete -c emberwall -n '__fish_seen_subcommand_from completion' -a ${fq(SHELLS.join(' '))}`,
  ];
  for (const c of COMMANDS) {
    for (const f of c.flags) {
      // Values with their own descriptions come from printf as "value<TAB>description" lines.
      const described = (xs: { id: string; about: string }[]) => `(printf '%s\\t%s\\n' ${xs.map((x) => `${x.id} ${q(x.about)}`).join(' ')})`;
      const values = f.value === 'profile' ? `-x -a ${fq(described(profiles()))}`
        : f.value === 'target' ? `-x -a ${fq(targetWords().join(' '))}`
        : f.value === 'dir' ? `-x -a '(__fish_complete_directories)'`
        : f.value === 'number' ? '-x' : '';
      lines.push(`complete -c emberwall -n '__fish_seen_subcommand_from ${c.name}' -l ${f.name} ${values} -d ${fq(f.about)}`.replace(/ {2,}/g, ' '));
    }
  }
  return `${lines.join('\n')}\n`;
}

export function completionScript(shell: Shell): string {
  return shell === 'bash' ? bash() : shell === 'zsh' ? zsh() : fish();
}
