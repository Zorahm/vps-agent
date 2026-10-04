// Checks vps-agent-mux against a real host: tool listing, forwarding, reconnection.
// usage: node tests/mux-accept.mjs <path to vps-agent-mux> <hosts.toml> <host name>
import { spawn, execFileSync } from "node:child_process";
import { createInterface } from "node:readline";

const [exe, config, host] = process.argv.slice(2);
const child = spawn(exe, ["serve", "--config", config], { stdio: ["pipe", "pipe", "inherit"] });
const pending = new Map();
createInterface({ input: child.stdout }).on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
});
let nextId = 1;
const rpc = (method, params) => new Promise((resolve, reject) => {
  const id = nextId++;
  const timer = setTimeout(() => reject(new Error(`timeout: ${method}`)), 90000);
  pending.set(id, (m) => { clearTimeout(timer); resolve(m); });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
});
const call = async (name, args = {}) => {
  const r = await rpc("tools/call", { name, arguments: args });
  if (r.error) return { isError: true, text: `PROTOCOL ERROR ${JSON.stringify(r.error)}` };
  return { isError: !!r.result.isError, text: (r.result.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n") };
};
let failed = 0;
const check = (label, cond, detail = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${cond ? "" : `\n      ${String(detail).slice(0, 500)}`}`);
  if (!cond) failed++;
};

// Kills the ssh processes the multiplexer started, to simulate a dropped link.
const killSshChildren = () => {
  if (process.platform === "win32") {
    const out = execFileSync("powershell", ["-NoProfile", "-Command",
      `Get-CimInstance Win32_Process -Filter "ParentProcessId=${child.pid}" | ForEach-Object { $_.ProcessId }`]).toString();
    const pids = out.split(/\s+/).filter(Boolean);
    for (const pid of pids) execFileSync("taskkill", ["/F", "/PID", pid], { stdio: "ignore" });
    return pids.length;
  }
  const out = execFileSync("pgrep", ["-P", String(child.pid)]).toString();
  const pids = out.split(/\s+/).filter(Boolean);
  for (const pid of pids) process.kill(Number(pid), "SIGKILL");
  return pids.length;
};

const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "mux-accept", version: "0" } });
check("initialize", !!init.result?.serverInfo, JSON.stringify(init));
child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

const tools = (await rpc("tools/list", {})).result.tools;
const exec = tools.find((t) => t.name === "exec");
check("tools/list has hosts plus the remote tools", tools.some((t) => t.name === "hosts") && tools.length > 20, `${tools.length} tools`);
check("remote tools gained a host parameter", exec?.inputSchema?.properties?.host?.enum?.includes(host), JSON.stringify(exec?.inputSchema));
check("annotations survive the proxy", exec?.annotations?.destructiveHint === true, JSON.stringify(exec?.annotations));

let r = await call("hosts");
check("hosts reports the connection", new RegExp(`${host} .*connected`).test(r.text), r.text);
r = await call("exec", { host, cmd: "id -un" });
check("exec is forwarded", !r.isError && /\nagent\n/.test(r.text), r.text);
r = await call("exec", { host: "no-such-host", cmd: "id" });
check("unknown host is refused locally", r.isError && /unknown host/.test(r.text), r.text);
r = await call("exec", { host, cmd: "id", as_user: "root" });
check("the server's own refusals pass through", r.isError, r.text);

const killed = killSshChildren();
check("simulated a dropped link", killed > 0, `killed ${killed}`);
await new Promise((res) => setTimeout(res, 1000));
r = await call("exec", { host, cmd: "echo back-again" });
check("the next call reconnects on its own", !r.isError && /back-again/.test(r.text), r.text);

console.log(failed === 0 ? "\nall mux checks passed" : `\n${failed} mux check(s) failed`);
child.stdin.end();
child.kill();
process.exit(failed === 0 ? 0 : 1);
