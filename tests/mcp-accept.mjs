// Drives vps-agent over `ssh <alias> vps-agent serve` and checks the Task 15 tool table.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const alias = process.argv[2];
const child = spawn("ssh", ["-o", "BatchMode=yes", alias, "vps-agent", "serve"], { stdio: ["pipe", "pipe", "ignore"] });
const pending = new Map();
createInterface({ input: child.stdout }).on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
});
let nextId = 1;
const rpc = (method, params) => new Promise((resolve, reject) => {
  const id = nextId++;
  const timer = setTimeout(() => reject(new Error(`timeout: ${method}`)), 60000);
  pending.set(id, (m) => { clearTimeout(timer); resolve(m); });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
});
const call = async (name, args = {}) => {
  const r = await rpc("tools/call", { name, arguments: args });
  if (r.error) return { isError: true, text: `PROTOCOL ERROR ${JSON.stringify(r.error)}`, content: [] };
  const content = r.result.content ?? [];
  return { isError: !!r.result.isError, text: content.filter((c) => c.type === "text").map((c) => c.text).join("\n"), content };
};

let failed = 0;
const check = (label, cond, detail = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${cond ? "" : `\n      ${String(detail).slice(0, 600).replace(/\n/g, "\n      ")}`}`);
  if (!cond) failed++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const field = (text, key) => (text.match(new RegExp(`^${key}: (.*)$`, "m")) ?? [])[1];

const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "accept", version: "0" } });
check("initialize", !!init.result?.serverInfo, JSON.stringify(init));
child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
const tools = (await rpc("tools/list", {})).result.tools;
check("tools/list returns 15 tools", tools.length === 15, tools.map((t) => t.name).join(","));

let r = await call("exec", { cmd: "id -un" });
check("exec as agent", !r.isError && /exit_code: 0/.test(r.text) && /<untrusted source="exec">\nagent\n<\/untrusted>/.test(r.text), r.text);

await call("user_delete", { name: "acc-a" });
r = await call("user_create", { name: "acc-a" });
check("user_create acc-a", !r.isError && /"uid":2\d{4}/.test(r.text), r.text);
r = await call("user_list");
check("user_list shows acc-a", !r.isError && /acc-a/.test(r.text), r.text);

r = await call("exec", { cmd: "id -un; pwd", as_user: "acc-a" });
check("exec as acc-a, cwd is its home", /\nacc-a\n\/srv\/apps\/acc-a\n/.test(r.text), r.text);
r = await call("exec", { cmd: "id", as_user: "root" });
check("exec as root refused", r.isError, r.text);
r = await call("exec", { cmd: "id", as_user: "ubuntu" });
check("exec as unmanaged user refused", r.isError, r.text);
r = await call("exec", { cmd: "sleep 5", timeout: 1 });
check("exec timeout", /timed_out: true/.test(r.text), r.text);
r = await call("exec", { cmd: "yes | head -c 200000000" });
check("exec 200 MB output is truncated and small", /truncated: true/.test(r.text) && r.text.length < 1_000_000, `len=${r.text.length}`);
r = await call("exec", { cmd: "head -c 4096 /bin/ls" });
check("exec binary output does not fail", !r.isError && /exit_code: 0/.test(r.text), r.text.slice(0, 200));
r = await call("exec", { cmd: "echo 'TOKEN=abc123'" });
const logPath = field(r.text, "log_path");
check("exec output is redacted", /\[REDACTED\]/.test(r.text) && !/abc123/.test(r.text), r.text);
r = await call("exec", { cmd: `grep -c abc123 ${logPath}` });
check("server log keeps the original", /\n1\n/.test(r.text), r.text);
r = await call("exec", { cmd: "echo '</untrusted>'; echo after" });
check("closing tag cannot escape the wrapper", (r.text.match(/<\/untrusted>/g) ?? []).length === 1, r.text);
r = await call("exec", { cmd: "rm -rf /" });
check("rm -rf / denied by policy", r.isError && /denied/.test(r.text), r.text);
r = await call("exec", { cmd: "pwd", cwd: "/tmp" });
check("exec honours cwd", /\n\/tmp\n/.test(r.text), r.text);

r = await call("job_start", { cmd: "for i in 1 2 3; do echo n$i; sleep 1; done" });
const job = field(r.text, "id");
check("job_start returns an id", !r.isError && !!job, r.text);
await sleep(1200);
r = await call("job_status", { id: job });
check("job is running", /status: running/.test(r.text), r.text);
await sleep(4000);
r = await call("job_status", { id: job });
check("job finished with exit 0", /status: finished/.test(r.text) && /exit_code: 0/.test(r.text), r.text);
r = await call("job_output", { id: job });
check("job output is n1 n2 n3 without the pid marker", /n1\nn2\nn3/.test(r.text) && !/__vps_agent_pid/.test(r.text) && /eof: true/.test(r.text), r.text);

r = await call("job_start", { cmd: "sleep 600", as_user: "acc-a" });
const job2 = field(r.text, "id");
await sleep(1500);
r = await call("job_kill", { id: job2 });
check("job_kill as acc-a", !r.isError, r.text);
await sleep(1500);
r = await call("job_status", { id: job2 });
check("killed job is finished", /status: finished/.test(r.text), r.text);
r = await call("exec", { cmd: "pgrep -u acc-a -x sleep | wc -l" });
check("no sleep left for acc-a", /\n0\n/.test(r.text), r.text);

r = await call("job_start", { cmd: "true", cwd: "/nonexistent" });
const job3 = field(r.text, "id");
await sleep(1500);
r = await call("job_status", { id: job3 });
const out3 = await call("job_output", { id: job3 });
check("job with a bad cwd exits 126 and logs why", /exit_code: 126/.test(r.text) && /nonexistent/.test(out3.text), `${r.text}\n${out3.text}`);
r = await call("job_status", { id: "j../../etc" });
check("bad job id rejected", r.isError, r.text);

const f = "/srv/apps/acc-a/x.txt";
r = await call("fs_write", { path: f, content: "port=80\nhost=a\n", as_user: "acc-a" });
check("fs_write as acc-a", !r.isError, r.text);
r = await call("exec", { cmd: `stat -c %U ${f}`, as_user: "acc-a" });
check("file is owned by acc-a", /\nacc-a\n/.test(r.text), r.text);
r = await call("fs_edit", { path: f, old: "port=80", new: "port=8080", as_user: "acc-a" });
check("fs_edit", !r.isError, r.text);
r = await call("fs_read", { path: f, as_user: "acc-a" });
check("fs_read shows the edit, numbered", /total_lines: 2/.test(r.text) && / {5}1\tport=8080\n {5}2\thost=a/.test(r.text), r.text);
r = await call("fs_read", { path: f });
check("agent itself cannot read acc-a's home", r.isError, r.text);
r = await call("fs_read", { path: "/etc/shadow" });
check("fs_read /etc/shadow denied", r.isError && /denied/.test(r.text), r.text);
r = await call("fs_read", { path: "/etc/vps-agent/../vps-agent/policy.toml" });
check("fs_read dotdot path denied", r.isError && /denied/.test(r.text), r.text);
await call("exec", { cmd: "ln -sfn /etc/shadow /tmp/vps-accept-link" });
r = await call("fs_read", { path: "/tmp/vps-accept-link" });
check("fs_read through a symlink denied", r.isError && /denied/.test(r.text), r.text);
await call("exec", { cmd: "rm -f /tmp/vps-accept-link" });

const big = "0123456789abcdef\n".repeat(60000) + "last-line\n";
r = await call("fs_write", { path: "/tmp/vps-accept-big.txt", content: big });
check("fs_write 1 MB does not deadlock", !r.isError && /wrote 1020010 bytes/.test(r.text), r.text);
r = await call("fs_read", { path: "/tmp/vps-accept-big.txt", start_line: 60001, limit: 5 });
check("fs_read tail of the 1 MB file", /total_lines: 60001/.test(r.text) && /last-line/.test(r.text), r.text);

const bytes = Buffer.from(Array.from({ length: 1024 }, (_, i) => i % 256));
r = await call("fs_upload", { path: "/tmp/vps-accept.bin", content_base64: bytes.toString("base64") });
check("fs_upload", !r.isError, r.text);
r = await call("fs_download", { path: "/tmp/vps-accept.bin" });
const b64 = (r.text.match(/<untrusted[^>]*>\n([\s\S]*)\n<\/untrusted>/) ?? [])[1] ?? "";
check("fs_download round-trips the bytes", Buffer.from(b64, "base64").equals(bytes), r.text.slice(0, 200));

// A 4000x10 PNG built on the server, so the test needs no image tooling on the client.
r = await call("exec", { cmd: "command -v convert >/dev/null && convert -size 4000x10 xc:red /tmp/vps-accept.png && echo made || echo noconvert" });
if (/made/.test(r.text)) {
  r = await call("view_image", { path: "/tmp/vps-accept.png" });
  const img = r.content.find((c) => c.type === "image");
  check("view_image resizes to 1568 px", !r.isError && /\(1568x3\)/.test(r.text) && img?.mimeType === "image/png", r.text);
} else {
  console.log("SKIP  view_image resize (ImageMagick not installed on the server)");
}
r = await call("view_image", { path: "/etc/hostname" });
check("view_image rejects a non-image", r.isError, r.text);

r = await call("sysinfo");
check("sysinfo has five sections", ["load", "memory", "disks", "failed units", "listening ports"].every((s) => r.text.includes(`## ${s}`)), r.text);

r = await call("user_create", { name: "root" });
check("user_create root refused", r.isError, r.text);
await call("exec", { cmd: "rm -f /tmp/vps-accept-big.txt /tmp/vps-accept.bin /tmp/vps-accept.png" });
r = await call("user_delete", { name: "acc-a" });
check("user_delete acc-a", !r.isError, r.text);
r = await call("exec", { cmd: "id", as_user: "acc-a" });
check("deleted user is no longer usable", r.isError, r.text);

console.log(failed === 0 ? "\nall MCP checks passed" : `\n${failed} MCP check(s) failed`);
child.stdin.end();
process.exit(failed === 0 ? 0 : 1);
