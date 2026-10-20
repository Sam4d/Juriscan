// Validation-only guard, never loaded by normal users. Fail on attempted network or subprocess use.
const { syncBuiltinESMExports } = require("node:module");
const blocked = () => {
  throw new Error("Offline validation forbids network and child processes");
};
for (const module of ["node:http", "node:https"]) {
  const m = require(module);
  m.request = blocked;
  m.get = blocked;
}
const net = require("node:net");
net.connect = blocked;
net.createConnection = blocked;
net.Socket.prototype.connect = blocked;
require("node:tls").connect = blocked;
const dns = require("node:dns");
dns.lookup = blocked;
dns.resolve = blocked;
for (const name of [
  "spawn",
  "spawnSync",
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "fork",
])
  require("node:child_process")[name] = blocked;
globalThis.fetch = blocked;
syncBuiltinESMExports();
