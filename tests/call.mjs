// Calls one vps-agent tool over `ssh <alias> vps-agent serve` and prints the result.
// usage: node tests/call.mjs <ssh alias> <tool> ['<json arguments>']
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const [alias, tool, json = "{}"] = process.argv.slice(2);
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
  const timer = setTimeout(() => reject(new Error(`timeout: ${method}`)), 120000);
  pending.set(id, (m) => { clearTimeout(timer); resolve(m); });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
});

await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "call", version: "0" } });
child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
const r = await rpc("tools/call", { name: tool, arguments: JSON.parse(json) });
if (r.error) {
  console.log(`PROTOCOL ERROR ${JSON.stringify(r.error)}`);
} else {
  if (r.result.isError) console.log("[tool error]");
  for (const c of r.result.content ?? []) console.log(c.type === "text" ? c.text : `[${c.type} ${c.mimeType ?? ""}]`);
}
child.stdin.end();
process.exit(r.error || r.result.isError ? 1 : 0);
