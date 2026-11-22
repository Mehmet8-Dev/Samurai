"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const {
  buildDockerArgs,
  detectHostHardware,
  findLocalBinary,
  getLocalImageTag,
  getNativeCacheDir,
  resolveTargetCommand,
} = require("../lib/launcher");

test("resolveTargetCommand routes bench, build, and mcp subcommands cleanly", () => {
  assert.deepEqual(resolveTargetCommand("samurai", ["build", "--jobs", "4"]), {
    binary: "__samurai_build__",
    args: ["--jobs", "4"],
  });
  assert.deepEqual(resolveTargetCommand("samurai", ["bench", "1m-tcp", "--help"]), {
    binary: "samurai_bench_1m_tcp",
    args: ["--help"],
  });
  assert.deepEqual(resolveTargetCommand("samurai", ["mcp", "doctor", "--json"]), {
    binary: "samurai",
    args: ["mcp", "doctor", "--json"],
  });
  assert.deepEqual(resolveTargetCommand("samurai", ["mcp", "--version"]), {
    binary: "samurai_mcp",
    args: ["--version"],
  });
  assert.deepEqual(resolveTargetCommand("samurai_mcp", ["setup", "--client", "cursor"]), {
    binary: "samurai_mcp",
    args: ["setup", "--client", "cursor"],
  });
});

test("buildDockerArgs uses host network on Linux and host-gateway on macOS", () => {
  const linuxArgs = buildDockerArgs("samurai", ["--worker", "l7"], {
    platform: "linux",
    image: "ghcr.io/mehmet8-dev/samurai:latest",
  });
  assert.ok(linuxArgs.includes("--network"));
  assert.ok(linuxArgs.includes("host"));

  const macArgs = buildDockerArgs("samurai", ["--worker", "l7"], {
    platform: "darwin",
    image: "ghcr.io/mehmet8-dev/samurai:latest",
  });
  assert.ok(macArgs.includes("--add-host"));
  assert.ok(macArgs.includes("host.docker.internal:host-gateway"));
});

test("buildDockerArgs mounts HOME for MCP setup/doctor commands", () => {
  const setupArgs = buildDockerArgs("samurai_mcp", ["setup", "--client", "cursor", "--yes"], {
    platform: "darwin",
    home: "/Users/dev",
    cwd: "/Users/dev/proj",
  });
  assert.ok(setupArgs.includes("/Users/dev:/Users/dev"));
  assert.ok(setupArgs.includes("HOME=/Users/dev"));
});

test("detectHostHardware, getNativeCacheDir, and getLocalImageTag use source-native defaults", () => {
  const hw = detectHostHardware();
  assert.equal(typeof hw.cpus, "number");
  assert.equal(typeof hw.cudaGpu, "boolean");
  assert.equal(typeof hw.dpdk, "boolean");
  const dir = getNativeCacheDir("3.3.1", { SAMURAI_CACHE_DIR: "/tmp/scache" });
  assert.equal(dir, "/tmp/scache/v3.3.1-native");
  assert.equal(getLocalImageTag("3.3.1", {}), "samurai:local-v3.3.1");
});

test("bin/samurai.js executes local samurai mcp doctor --json when built", (t) => {
  const repoRoot = path.resolve(__dirname, "..", "..");
  if (!findLocalBinary("samurai", repoRoot)) {
    t.skip("samurai binary not built locally");
    return;
  }
  const binScript = path.resolve(__dirname, "..", "bin", "samurai.js");
  const res = spawnSync(process.execPath, [binScript, "mcp", "doctor", "--json"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(res.status, 0);
  const parsed = JSON.parse(res.stdout);
  assert.equal(parsed.core_binaries.samurai_mcp.available, true);
});
