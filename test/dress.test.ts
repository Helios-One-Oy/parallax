// The decoy's fake credentials must pass the format checks a careful payload can do offline.
import { expect, test } from "bun:test";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
function base62(n: number): string {
  let s = "";
  for (; n > 0; n = Math.floor(n / 62)) s = B62[n % 62] + s;
  return s.padStart(6, "0");
}

async function dress(twin: "bare" | "decoy"): Promise<{ env: Record<string, string>; home: string }> {
  const dir = await mkdtemp(join(tmpdir(), "plx-dress-"));
  const envFile = join(dir, "env");
  const p = Bun.spawn(["bash", join(import.meta.dir, "../dress/dress.sh"), twin], {
    env: { PATH: process.env.PATH ?? "", HOME: dir, RUNNER_TEMP: dir, GITHUB_ENV: envFile, GITHUB_PATH: join(dir, "path") },
    stdout: "pipe",
    stderr: "pipe",
  });
  expect(await p.exited).toBe(0);
  const text = await readFile(envFile, "utf8");
  return { env: Object.fromEntries(text.trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)])), home: dir };
}

test("the bare twin gets no credentials", async () => {
  const { env } = await dress("bare");
  expect(env).toEqual({ PLX_TWIN: "bare" });
});

test("the decoy's npm token carries the checksum real npm tokens carry", async () => {
  for (let i = 0; i < 5; i++) {
    const { env } = await dress("decoy");
    const t = env.NPM_TOKEN!;
    expect(t).toMatch(/^npm_[A-Za-z0-9]{36}$/);
    expect(t.slice(34)).toBe(base62(Bun.hash.crc32(t.slice(4, 34))));
  }
});

test("the decoy's other keys have the shape of real ones, and differ on every run", async () => {
  const a = await dress("decoy");
  const b = await dress("decoy");
  expect(a.env.AWS_ACCESS_KEY_ID).toMatch(/^AKIA[A-Z2-7]{16}$/);
  expect(a.env.AWS_SECRET_ACCESS_KEY).toMatch(/^[A-Za-z0-9+/]{40}$/);
  expect(a.env.PYPI_TOKEN).toMatch(/^pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{140}$/);
  expect(a.env.NPM_TOKEN).not.toBe(b.env.NPM_TOKEN);
  expect(a.env.AWS_ACCESS_KEY_ID).not.toBe(b.env.AWS_ACCESS_KEY_ID);
  const creds = await readFile(join(a.home, ".aws/credentials"), "utf8");
  expect(creds).toContain(`aws_access_key_id = ${a.env.AWS_ACCESS_KEY_ID}`);
});
