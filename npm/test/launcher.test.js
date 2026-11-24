"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const {
  DEFAULT_BUILD_CACHE_VOLUME,
  DEFAULT_GHCR_SOURCE_IMAGE,
  buildDockerArgs,
  buildExecEnv,
  detectConfiguredOptionalTargets,
  detectHostHardware,
  findLocalBinary,
  getLocalImageTag,
  getNativeCacheDir,
  resolveTargetCommand,
} = require("../lib/launcher");
const {
  executeSetup,
  resolveClientConfigPath,
} = require("../lib/mcp_setup");

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

test("buildDockerArgs uses host network on Linux and host-gateway on macOS/Windows", () => {
  const linuxArgs = buildDockerArgs("samurai", ["--worker", "l7"], {
    platform: "linux",
    image: "samurai:local-v3.3.3",
  });
  assert.ok(linuxArgs.includes("--network"));
  assert.ok(linuxArgs.includes("host"));

  const winArgs = buildDockerArgs("samurai", ["--worker", "l7"], {
    platform: "win32",
    image: DEFAULT_GHCR_SOURCE_IMAGE,
  });
  assert.ok(winArgs.includes(DEFAULT_BUILD_CACHE_VOLUME));
  assert.ok(winArgs.includes("--add-host"));
  assert.ok(winArgs.includes("host.docker.internal:host-gateway"));
  assert.ok(winArgs.includes(DEFAULT_GHCR_SOURCE_IMAGE));
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
  const dir = getNativeCacheDir("3.3.3", { SAMURAI_CACHE_DIR: "/tmp/scache" });
  assert.equal(dir, "/tmp/scache/v3.3.3-native");
  assert.equal(getLocalImageTag("3.3.3", {}), "samurai:local-v3.3.3");
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

test("detectConfiguredOptionalTargets discovers CUDA and AF_XDP targets configured by CMake", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "samurai-opt-"));
  try {
    fs.mkdirSync(path.join(tmpDir, "optional", "CMakeFiles", "gpu_packet_cuda.dir"), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, "optional", "CMakeFiles", "gpu_packet_cuda_defense.dir"), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, "optional", "CMakeFiles", "xdp_sender.dir"), { recursive: true });
    assert.deepEqual(detectConfiguredOptionalTargets(tmpDir), [
      "gpu_packet_cuda",
      "gpu_packet_cuda_defense",
      "xdp_sender",
    ]);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("buildExecEnv wires native GPU, defense CUDA, and AF_XDP shared libraries when present", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "samurai-env-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "libgpu_packet_cuda.so"), "");
    fs.writeFileSync(path.join(tmpDir, "libgpu_packet_cuda_defense.so"), "");
    fs.writeFileSync(path.join(tmpDir, "xdp_sender.so"), "");

    const env = buildExecEnv(tmpDir, { PATH: "/usr/bin" });
    assert.equal(env.SAMURAI_GPU_NATIVE_LIB, path.join(tmpDir, "libgpu_packet_cuda.so"));
    assert.equal(env.SAMURAI_GPU_DEFENSE_LIB, path.join(tmpDir, "libgpu_packet_cuda_defense.so"));
    assert.equal(env.SAMURAI_XDP_NATIVE_LIB, path.join(tmpDir, "xdp_sender.so"));
    assert.ok(env.LD_LIBRARY_PATH.startsWith(tmpDir));

    const preserved = buildExecEnv(tmpDir, { PATH: "/usr/bin", SAMURAI_GPU_NATIVE_LIB: "/custom/gpu.so" });
    assert.equal(preserved.SAMURAI_GPU_NATIVE_LIB, "/custom/gpu.so");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("mcp_setup configures Windows IDE & CLI paths with local Docker host-gateway", () => {
  assert.equal(
    resolveClientConfigPath(
      { id: "vscode", supportsProjectScope: true },
      { hostOs: "windows", scope: "user", home: "C:\\Users\\mehmet", appData: "C:\\Users\\mehmet\\AppData\\Roaming" }
    ),
    "C:\\Users\\mehmet\\AppData\\Roaming\\Code\\User\\mcp.json"
  );
  assert.equal(
    resolveClientConfigPath(
      { id: "claude_desktop", supportsProjectScope: false },
      { hostOs: "windows", scope: "user", home: "C:\\Users\\mehmet", appData: "C:\\Users\\mehmet\\AppData\\Roaming" }
    ),
    "C:\\Users\\mehmet\\AppData\\Roaming\\Claude\\claude_desktop_config.json"
  );

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "samurai-win-mcp-"));
  try {
    const appDataDir = path.join(tmpDir, "AppData", "Roaming");
    fs.mkdirSync(path.join(appDataDir, "Code", "User"), { recursive: true });
    fs.writeFileSync(
      path.join(appDataDir, "Code", "User", "mcp.json"),
      JSON.stringify({ servers: { existing: { type: "stdio", command: "echo" } } })
    );

    const res = executeSetup({
      client: "vscode",
      hostOs: "windows",
      imageTag: "samurai:local-v3.3.3",
      yes: true,
      homeOverride: tmpDir,
      projectOverride: tmpDir,
      appDataOverride: appDataDir,
    });
    assert.equal(res.ok, true);
    assert.equal(res.report.transport_mode, "docker");
    assert.equal(res.report.backup_created, true);
    assert.ok(res.report.proposed_entry.args.includes(DEFAULT_BUILD_CACHE_VOLUME));
    assert.ok(res.report.proposed_entry.args.includes("--add-host"));
    assert.ok(res.report.proposed_entry.args.includes("host.docker.internal:host-gateway"));
    assert.ok(res.report.proposed_entry.args.includes("samurai:local-v3.3.3"));

    const written = JSON.parse(fs.readFileSync(res.report.config_path, "utf8"));
    assert.ok(written.servers.existing);
    assert.equal(written.servers.samurai.command, "docker");

    const npxRes = executeSetup({
      client: "cursor",
      hostOs: "windows",
      npx: true,
      dryRun: true,
      homeOverride: tmpDir,
      projectOverride: tmpDir,
    });
    assert.equal(npxRes.ok, true);
    assert.equal(npxRes.report.proposed_entry.command, "npx.cmd");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
