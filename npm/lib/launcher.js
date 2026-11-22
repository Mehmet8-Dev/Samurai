"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const PKG = require("../package.json");

const DEFAULT_REPO = "Mehmet8-Dev/Samurai";
const DEFAULT_IMAGE = "ghcr.io/mehmet8-dev/samurai:latest";

const LOCAL_SUBDIRS = [
  "build/cli",
  "build/mcp",
  "build/control/daemon",
  "build/zmq",
  "build/l4",
];

const NATIVE_BUILD_TARGETS = [
  "samurai",
  "samurai_mcp",
  "samurai_master",
  "samurai_slave",
  "samurai_cpu_worker",
  "samurai_afpacket_worker",
  "samurai_afxdp_worker",
  "samurai_dpdk_worker",
  "samurai_gpu_worker",
  "samurai_doca_worker",
  "samurai_l7_worker",
  "samurai_scenario_worker",
  "samurai_defense_worker",
  "samurai_telco_worker",
  "test_100k_tcp_flows",
  "test_1m_tcp_flows",
  "bench_l7_stateful_userspace",
];

function isExecutable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function findInPath(cmd) {
  const pathEnv = process.env.PATH || "";
  const extList = process.platform === "win32" ? [".exe", ".cmd", ".bat", ""] : [""];
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of extList) {
      const candidate = path.join(dir, cmd + ext);
      if (isExecutable(candidate)) return candidate;
    }
  }
  return null;
}

function getCacheRoot(env = process.env) {
  if (env.SAMURAI_CACHE_DIR) return env.SAMURAI_CACHE_DIR;
  return path.join(os.homedir(), ".cache", "samurai");
}

function getNativeCacheDir(version = PKG.version, env = process.env) {
  const tag = version.startsWith("v") ? version : `v${version}`;
  return path.join(getCacheRoot(env), `${tag}-native`);
}

function pkgConfigExists(mod) {
  const res = spawnSync("pkg-config", ["--exists", mod], { stdio: "ignore" });
  return res.status === 0;
}

/**
 * Probe host CPU, GPU, kernel-bypass toolchains, and compiler availability so
 * native builds adapt to the exact machine running Samurai.
 */
function detectHostHardware() {
  const hw = {
    platform: process.platform,
    arch: process.arch,
    cpus: os.cpus().length || 1,
    avx2: false,
    avx512: false,
    cmake: Boolean(findInPath("cmake")),
    cxx: Boolean(findInPath("g++") || findInPath("clang++") || findInPath("c++")),
    nvcc: Boolean(findInPath("nvcc") || isExecutable("/usr/local/cuda/bin/nvcc")),
    cudaGpu: fs.existsSync("/dev/nvidia0"),
    dpdk: fs.existsSync("/usr/include/rte_eal.h") || fs.existsSync("/usr/include/dpdk/rte_config.h") || pkgConfigExists("libdpdk"),
    afXdp: fs.existsSync("/usr/include/bpf/bpf.h") || fs.existsSync("/usr/include/xdp/xsk.h"),
    ioUring: fs.existsSync("/usr/include/linux/io_uring.h") || fs.existsSync("/usr/include/x86_64-linux-gnu/linux/io_uring.h"),
    doca: fs.existsSync("/opt/mellanox/doca"),
  };

  if (process.platform === "linux") {
    try {
      const cpuinfo = fs.readFileSync("/proc/cpuinfo", "utf8");
      hw.avx2 = /\bavx2\b/.test(cpuinfo);
      hw.avx512 = /\bavx512f\b/.test(cpuinfo);
    } catch {
      // Ignore unreadable /proc/cpuinfo in restricted containers
    }
  }
  return hw;
}

/**
 * Resolve friendly wrapper commands like `samurai-net bench 1m-tcp` or
 * `samurai-net mcp` onto the underlying native binary + arguments.
 */
function resolveTargetCommand(defaultBinary, argv) {
  if (defaultBinary === "samurai" && argv.length > 0) {
    if (argv[0] === "build") {
      return { binary: "__samurai_build__", args: argv.slice(1) };
    }
    if (argv[0] === "bench" || argv[0] === "benchmark") {
      const sub = argv[1] || "";
      const benchMap = {
        "1m-tcp": "samurai_bench_1m_tcp",
        "100k-tcp": "samurai_bench_100k_tcp",
        "l7": "samurai_bench_l7",
      };
      if (benchMap[sub]) {
        return { binary: benchMap[sub], args: argv.slice(2) };
      }
    }
    if (argv[0] === "mcp") {
      const sub = argv[1] || "";
      if (sub !== "doctor" && sub !== "setup") {
        return { binary: "samurai_mcp", args: argv.slice(1) };
      }
    }
  }
  return { binary: defaultBinary, args: argv };
}

function findLocalBinary(binaryName, cwd = process.cwd(), env = process.env) {
  const altNames = [binaryName];
  if (binaryName === "samurai_bench_1m_tcp") altNames.push("test_1m_tcp_flows");
  if (binaryName === "samurai_bench_100k_tcp") altNames.push("test_100k_tcp_flows");
  if (binaryName === "samurai_bench_l7") altNames.push("bench_l7_stateful_userspace");

  const searchDirs = [];
  if (env.SAMURAI_BIN_DIR) searchDirs.push(env.SAMURAI_BIN_DIR);

  const nativeBinDir = path.join(getNativeCacheDir(PKG.version, env), "bin");
  if (fs.existsSync(path.join(nativeBinDir, ".native-verified"))) {
    searchDirs.push(nativeBinDir);
  }

  for (const sub of LOCAL_SUBDIRS) {
    searchDirs.push(path.join(cwd, sub));
    searchDirs.push(path.resolve(__dirname, "..", "..", sub));
  }
  searchDirs.push("/usr/local/bin");

  for (const name of altNames) {
    for (const dir of searchDirs) {
      const cand = path.join(dir, name);
      if (isExecutable(cand)) return cand;
    }
  }
  return null;
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

async function downloadToFile(url, destPath) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} fetching ${url}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(destPath, buf);
}

/**
 * Compile all Samurai binaries + workers natively on the target host so CPU SIMD
 * (`-march=native`), CUDA, DPDK, AF_XDP, io_uring, and DOCA match this machine.
 */
async function buildNativeForHost(version, rawArgs = [], env = process.env) {
  const tag = version.startsWith("v") ? version : `v${version}`;
  const repo = env.SAMURAI_REPO || DEFAULT_REPO;
  const hw = detectHostHardware();

  let portable = false;
  let force = false;
  let dockerLocalBuild = false;
  let jobs = String(hw.cpus);
  for (let i = 0; i < rawArgs.length; ++i) {
    const a = rawArgs[i];
    if (a === "--portable") portable = true;
    else if (a === "--force") force = true;
    else if (a === "--docker") dockerLocalBuild = true;
    else if ((a === "--jobs" || a === "-j") && i + 1 < rawArgs.length) jobs = rawArgs[++i];
    else if (a === "-h" || a === "--help") {
      process.stdout.write(
        "Usage: samurai-net build [--jobs N] [--portable] [--force] [--docker]\n\n" +
          "Compiles Samurai natively for this host's CPU (-march=native), CUDA, DPDK,\n" +
          "AF_XDP, io_uring, and DOCA hardware into ~/.cache/samurai/<ver>-native/.\n"
      );
      return 0;
    }
  }

  const nativeDir = getNativeCacheDir(version, env);
  const nativeBinDir = path.join(nativeDir, "bin");
  const marker = path.join(nativeBinDir, ".native-verified");
  if (!force && !dockerLocalBuild && fs.existsSync(marker) && isExecutable(path.join(nativeBinDir, "samurai"))) {
    process.stderr.write(`[samurai-net] Host-native build already present at ${nativeBinDir} (pass --force to rebuild).\n`);
    return 0;
  }

  if (dockerLocalBuild) {
    const dockerBin = findInPath("docker");
    if (!dockerBin) {
      process.stderr.write("[samurai-net] 'docker' is required for `build --docker`.\n");
      return 1;
    }
    const localRepoCmake = path.resolve(__dirname, "..", "..", "samurai", "CMakeLists.txt");
    if (!fs.existsSync(localRepoCmake)) {
      process.stderr.write("[samurai-net] Run `build --docker` from a cloned Samurai repository containing Dockerfile.\n");
      return 1;
    }
    const repoRoot = path.resolve(__dirname, "..", "..");
    const archArg = portable ? "OFF" : "ON";
    process.stderr.write(`[samurai-net] Building Docker image locally on target host (SAMURAI_NATIVE_ARCH=${archArg})...\n`);
    return execBinary(
      dockerBin,
      ["build", "--build-arg", `SAMURAI_NATIVE_ARCH=${archArg}`, "-t", env.SAMURAI_IMAGE || DEFAULT_IMAGE, repoRoot],
      null
    );
  }

  if (process.platform !== "linux") {
    process.stderr.write(
      `[samurai-net] Native host build targets Linux hosts. On ${process.platform}, Samurai runs via Docker or 'build --docker'.\n`
    );
    return 1;
  }

  if (!hw.cmake || !hw.cxx) {
    process.stderr.write(
      "[samurai-net] Missing build tools (cmake and g++/clang++).\n" +
        "Install prerequisites on Ubuntu/Debian:\n" +
        "  sudo apt update && sudo apt install -y build-essential cmake pkg-config libzmq3-dev libssl-dev " +
        "libhiredis-dev libpcap-dev libnghttp2-dev libngtcp2-dev libngtcp2-crypto-gnutls-dev libnghttp3-dev libgnutls28-dev liburing-dev\n"
    );
    return 1;
  }

  // Locate source tree (local checkout first, otherwise download GitHub tag archive).
  let srcRoot = null;
  const cwdSamurai = path.join(process.cwd(), "samurai", "CMakeLists.txt");
  const pkgRepoSamurai = path.resolve(__dirname, "..", "..", "samurai", "CMakeLists.txt");
  if (fs.existsSync(cwdSamurai)) srcRoot = process.cwd();
  else if (fs.existsSync(pkgRepoSamurai)) srcRoot = path.resolve(__dirname, "..", "..");
  else {
    srcRoot = path.join(getCacheRoot(env), "src", tag);
    if (force || !fs.existsSync(path.join(srcRoot, "samurai", "CMakeLists.txt"))) {
      fs.rmSync(srcRoot, { recursive: true, force: true });
      fs.mkdirSync(srcRoot, { recursive: true });
      const archiveUrl = `https://github.com/${repo}/archive/refs/tags/${tag}.tar.gz`;
      const tarTmp = path.join(os.tmpdir(), `samurai-src-${tag}-${process.pid}.tar.gz`);
      try {
        process.stderr.write(`[samurai-net] Downloading source archive ${archiveUrl}...\n`);
        await downloadToFile(archiveUrl, tarTmp);
        const ex = spawnSync("tar", ["-xzf", tarTmp, "--strip-components=1", "-C", srcRoot], { stdio: "inherit" });
        if (ex.status !== 0) throw new Error(`tar exited with ${ex.status}`);
      } finally {
        fs.rmSync(tarTmp, { force: true });
      }
    }
  }

  const buildDir = path.join(getCacheRoot(env), "build", tag);
  process.stderr.write(
    `[samurai-net] Host hardware: arch=${hw.arch}, cores=${hw.cpus}, avx2=${hw.avx2}, avx512=${hw.avx512}, ` +
      `cuda_gpu=${hw.cudaGpu}, nvcc=${hw.nvcc}, dpdk=${hw.dpdk}, af_xdp=${hw.afXdp}, io_uring=${hw.ioUring}, doca=${hw.doca}\n`
  );

  const cmakeCfg = spawnSync(
    "cmake",
    [
      "-S",
      path.join(srcRoot, "samurai"),
      "-B",
      buildDir,
      "-DCMAKE_BUILD_TYPE=Release",
      `-DSAMURAI_NATIVE_ARCH=${portable ? "OFF" : "ON"}`,
    ],
    { stdio: "inherit" }
  );
  if (cmakeCfg.status !== 0) return cmakeCfg.status || 1;

  // Build core targets plus whichever hardware backends this host supports.
  const targetsToBuild = [...NATIVE_BUILD_TARGETS];
  const cmakeBuild = spawnSync("cmake", ["--build", buildDir, "-j", jobs, "--target", ...targetsToBuild], {
    stdio: "inherit",
  });
  if (cmakeBuild.status !== 0) return cmakeBuild.status || 1;

  fs.mkdirSync(nativeBinDir, { recursive: true });
  const copyMap = [
    ["cli/samurai", "samurai"],
    ["mcp/samurai_mcp", "samurai_mcp"],
    ["control/daemon/samurai_master", "samurai_master"],
    ["control/daemon/samurai_slave", "samurai_slave"],
    ["zmq/samurai_cpu_worker", "samurai_cpu_worker"],
    ["zmq/samurai_afpacket_worker", "samurai_afpacket_worker"],
    ["zmq/samurai_afxdp_worker", "samurai_afxdp_worker"],
    ["zmq/samurai_dpdk_worker", "samurai_dpdk_worker"],
    ["zmq/samurai_gpu_worker", "samurai_gpu_worker"],
    ["zmq/samurai_doca_worker", "samurai_doca_worker"],
    ["zmq/samurai_l7_worker", "samurai_l7_worker"],
    ["zmq/samurai_scenario_worker", "samurai_scenario_worker"],
    ["zmq/samurai_defense_worker", "samurai_defense_worker"],
    ["zmq/samurai_telco_worker", "samurai_telco_worker"],
    ["l4/test_100k_tcp_flows", "samurai_bench_100k_tcp"],
    ["l4/test_1m_tcp_flows", "samurai_bench_1m_tcp"],
    ["zmq/bench_l7_stateful_userspace", "samurai_bench_l7"],
  ];
  for (const [rel, name] of copyMap) {
    const src = path.join(buildDir, rel);
    if (fs.existsSync(src)) {
      const dst = path.join(nativeBinDir, name);
      fs.copyFileSync(src, dst);
      fs.chmodSync(dst, 0o755);
    }
  }
  const cudaSo = path.join(srcRoot, "samurai", "libgpu_packet_cuda.so");
  if (fs.existsSync(cudaSo)) {
    fs.copyFileSync(cudaSo, path.join(nativeBinDir, "libgpu_packet_cuda.so"));
  }
  const srcSkills = path.join(srcRoot, "skills");
  if (fs.existsSync(srcSkills)) {
    fs.cpSync(srcSkills, path.join(nativeDir, "skills"), { recursive: true, force: true });
  }
  fs.writeFileSync(marker, `${tag}\n`);
  process.stderr.write(`[samurai-net] Host-native binaries ready at ${nativeBinDir}\n`);
  return 0;
}

/**
 * Ensure the Linux x86_64 GitHub Release bundle is cached and verified by SHA-256.
 * Returns the extracted `bin/` directory on success, or null if unavailable.
 */
async function ensureCachedLinuxRelease(version, env = process.env) {
  const tag = version.startsWith("v") ? version : `v${version}`;
  const repo = env.SAMURAI_REPO || DEFAULT_REPO;
  const cacheDir = path.join(getCacheRoot(env), tag);
  const binDir = path.join(cacheDir, "bin");
  const marker = path.join(cacheDir, ".verified");

  if (fs.existsSync(marker) && isExecutable(path.join(binDir, "samurai"))) {
    return binDir;
  }

  const tarName = `samurai-${tag}-linux-x86_64.tar.gz`;
  const baseUrl = `https://github.com/${repo}/releases/download/${tag}`;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "samurai-net-"));

  try {
    const tarPath = path.join(tmpDir, tarName);
    const shaPath = path.join(tmpDir, `${tarName}.sha256`);

    process.stderr.write(`[samurai-net] Downloading ${tarName} from GitHub Releases...\n`);
    await downloadToFile(`${baseUrl}/${tarName}`, tarPath);

    try {
      await downloadToFile(`${baseUrl}/${tarName}.sha256`, shaPath);
      const expected = fs.readFileSync(shaPath, "utf8").trim().split(/\s+/)[0].toLowerCase();
      const actual = sha256File(tarPath).toLowerCase();
      if (!expected || expected !== actual) {
        throw new Error(`SHA-256 mismatch for ${tarName}: expected ${expected}, got ${actual}`);
      }
    } catch (err) {
      if (String(err.message || err).includes("SHA-256 mismatch")) throw err;
    }

    fs.mkdirSync(cacheDir, { recursive: true });
    const extract = spawnSync("tar", ["-xzf", tarPath, "--strip-components=1", "-C", cacheDir], {
      stdio: "inherit",
    });
    if (extract.status !== 0) {
      throw new Error(`tar extraction exited with status ${extract.status}`);
    }
    fs.writeFileSync(marker, `${tag}\n`);
    return binDir;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function buildDockerArgs(binary, args, opts = {}) {
  const platform = opts.platform || process.platform;
  const image = opts.image || process.env.SAMURAI_IMAGE || DEFAULT_IMAGE;
  const cwd = opts.cwd || process.cwd();
  const home = opts.home || os.homedir();
  const isMcpConfigCmd =
    (binary === "samurai_mcp" && (args[0] === "setup" || args[0] === "doctor")) ||
    (binary === "samurai" && args[0] === "mcp" && (args[1] === "setup" || args[1] === "doctor"));

  const dockerArgs = ["run", "--rm", "-i"];
  if (isMcpConfigCmd) {
    if (typeof process.getuid === "function" && typeof process.getgid === "function") {
      dockerArgs.push("-u", `${process.getuid()}:${process.getgid()}`);
    }
    dockerArgs.push("-v", `${home}:${home}`, "-v", `${cwd}:${cwd}`, "-w", cwd, "-e", `HOME=${home}`);
  } else if (platform === "linux") {
    dockerArgs.push("--network", "host");
  } else {
    dockerArgs.push("--add-host", "host.docker.internal:host-gateway");
  }

  dockerArgs.push(image, binary, ...args);
  return dockerArgs;
}

function execBinary(binPath, args, extraBinDir) {
  const env = { ...process.env };
  if (extraBinDir) {
    env.SAMURAI_BIN_DIR = extraBinDir;
    env.PATH = `${extraBinDir}${path.delimiter}${env.PATH || ""}`;
  }
  const res = spawnSync(binPath, args, { stdio: "inherit", env });
  if (res.error) {
    process.stderr.write(`[samurai-net] Failed to execute ${binPath}: ${res.error.message}\n`);
    return 1;
  }
  if (res.signal) {
    process.kill(process.pid, res.signal);
    return 1;
  }
  return typeof res.status === "number" ? res.status : 1;
}

function maybeHintNativeHardware(binary, args) {
  if (!process.stderr.isTTY) return;
  if (binary === "samurai_mcp" && args.length === 0) return;  // keep MCP stdio quiet
  const hw = detectHostHardware();
  if (hw.cudaGpu || hw.nvcc || hw.dpdk || hw.doca || hw.avx512) {
    process.stderr.write(
      "[samurai-net] Host acceleration detected (CUDA/DPDK/DOCA/AVX-512). " +
        "Run 'npx -y samurai-net build' to compile hardware-optimized binaries for this machine.\n"
    );
  }
}

async function runCli(defaultBinary, rawArgv) {
  const { binary, args } = resolveTargetCommand(defaultBinary, rawArgv);
  if (binary === "__samurai_build__") {
    return buildNativeForHost(PKG.version, args);
  }

  const forceDocker = process.env.SAMURAI_DOCKER === "1";
  const wantNativeAuto = process.env.SAMURAI_BUILD_NATIVE === "1";

  if (!forceDocker) {
    const localBin = findLocalBinary(binary);
    if (localBin) {
      return execBinary(localBin, args, path.dirname(localBin));
    }

    if (wantNativeAuto && process.platform === "linux") {
      const brc = await buildNativeForHost(PKG.version, []);
      if (brc === 0) {
        const builtBin = findLocalBinary(binary);
        if (builtBin) return execBinary(builtBin, args, path.dirname(builtBin));
      }
    }

    if (process.platform === "linux" && process.arch === "x64") {
      try {
        const cachedBinDir = await ensureCachedLinuxRelease(PKG.version);
        if (cachedBinDir) {
          const cachedBin = path.join(cachedBinDir, binary);
          if (isExecutable(cachedBin)) {
            maybeHintNativeHardware(binary, args);
            return execBinary(cachedBin, args, cachedBinDir);
          }
        }
      } catch (err) {
        process.stderr.write(`[samurai-net] Native release unavailable (${err.message}); falling back to Docker...\n`);
      }
    }
  }

  const dockerBin = findInPath("docker");
  if (!dockerBin) {
    process.stderr.write(
      `[samurai-net] Could not locate native '${binary}' binary and 'docker' was not found in PATH.\n` +
        `Compile natively on this host with:\n` +
        `  npx -y samurai-net build\n`
    );
    return 1;
  }

  const dockerArgs = buildDockerArgs(binary, args);
  return execBinary(dockerBin, dockerArgs, null);
}

module.exports = {
  buildDockerArgs,
  buildNativeForHost,
  detectHostHardware,
  ensureCachedLinuxRelease,
  findLocalBinary,
  getNativeCacheDir,
  resolveTargetCommand,
  runCli,
  sha256File,
};
