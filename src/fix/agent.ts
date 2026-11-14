// The agent that writes the fix. It is not trusted: it works in a throwaway checkout, may only run
// npm against the lockfile (no install scripts, no node_modules) and edit package.json, and what it
// leaves behind is checked by Parallax before anything is proposed.
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

export type AgentInput = { cwd: string; prompt: string; home: string; model?: string; timeoutMs?: number };
export type AgentResult = { ok: boolean; report: string; model: string; turns: number; seconds: number; error: string | null };
export type Agent = (input: AgentInput) => Promise<AgentResult>;

export const AGENT_MODEL = "claude-fable-5-2";

/** What the agent may do without asking. Reading inside the checkout is allowed by default. */
export const AGENT_TOOLS = [
  "Edit(package.json)",
  "Bash(npm view:*)",
  "Bash(npm ls:*)",
  "Bash(npm explain:*)",
  "Bash(npm outdated:*)",
  "Bash(npm audit:*)",
  "Bash(npm update:*)",
  "Bash(npm install:*)",
  "Bash(npm pkg:*)",
];

/** npm settings forced on every command the agent runs: lockfile only, never run package code. */
export const AGENT_NPM_ENV = {
  npm_config_ignore_scripts: "true",
  npm_config_package_lock_only: "true",
  npm_config_fund: "false",
  npm_config_update_notifier: "false",
};

export const claudeAgent: Agent = async ({ cwd, prompt, home, model = AGENT_MODEL, timeoutMs = 15 * 60_000 }) => {
  const key = process.env.PLX_AGENT_API_KEY || process.env.CLIPROXY_API_KEY || process.env.ANTHROPIC_API_KEY || "";
  const baseUrl = process.env.PLX_AGENT_BASE_URL || process.env.ANTHROPIC_BASE_URL || "";
  if (!key) return { ok: false, report: "", model, turns: 0, seconds: 0, error: "No key for the agent: set PLX_AGENT_API_KEY" };
  await mkdir(join(home, "claude"), { recursive: true });
  const started = Date.now();
  const proc = Bun.spawn(
    ["claude", "-p", "--model", model, "--output-format", "json", "--strict-mcp-config", "--allowedTools", ...AGENT_TOOLS],
    {
      cwd,
      stdin: new Blob([prompt]),
      stdout: "pipe",
      stderr: "pipe",
      // A clean environment: nothing of the caller's reaches the agent except what is listed here.
      env: {
        PATH: process.env.PATH ?? "",
        HOME: home,
        CLAUDE_CONFIG_DIR: join(home, "claude"),
        npm_config_cache: join(home, "npm-cache"),
        ANTHROPIC_API_KEY: key,
        ...(baseUrl ? { ANTHROPIC_BASE_URL: baseUrl } : {}),
        ...AGENT_NPM_ENV,
      },
    },
  );
  const timer = setTimeout(() => proc.kill(), timeoutMs);
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  clearTimeout(timer);
  const seconds = Math.round((Date.now() - started) / 1000);
  try {
    const d = JSON.parse(out) as { result?: string; is_error?: boolean; num_turns?: number; modelUsage?: Record<string, unknown> };
    const used = Object.keys(d.modelUsage ?? {});
    return {
      ok: code === 0 && !d.is_error,
      report: d.result ?? "",
      model: used.includes(model) || used.length === 0 ? model : used.join(", "),
      turns: d.num_turns ?? 0,
      seconds,
      error: code === 0 && !d.is_error ? null : (d.result ?? `agent exited ${code}`),
    };
  } catch {
    return { ok: false, report: "", model, turns: 0, seconds, error: `agent exited ${code}: ${(err || out).slice(0, 400)}` };
  }
};
