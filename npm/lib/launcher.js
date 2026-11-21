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

/**
 * Resolve friendly wrapper commands like `samurai-net bench 1m-tcp` or
 * `samurai-net mcp` onto the underlying native binary + arguments.
 */
function resolveTargetCommand(defaultBinary, argv) {
  if (defaultBinary === "samurai" && argv.length > 0) {
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
      // `samurai` handles `mcp doctor` and `mcp setup` directly; stdio MCP server
      // (`samurai-net mcp` or `samurai-net mcp --help`) routes to `samurai_mcp`.
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

function getCacheRoot(env = process.env) {
  if (env.SAMURAI_CACHE_DIR) return env.SAMURAI_CACHE_DIR;
  return path.join(os.homedir(), ".cache", "samurai");
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

    // Verify checksum when .sha256 asset is published alongside the tarball.
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

async function runCli(defaultBinary, rawArgv) {
  const { binary, args } = resolveTargetCommand(defaultBinary, rawArgv);
  const forceDocker = process.env.SAMURAI_DOCKER === "1";

  if (!forceDocker) {
    const localBin = findLocalBinary(binary);
    if (localBin) {
      return execBinary(localBin, args, path.dirname(localBin));
    }

    if (process.platform === "linux" && process.arch === "x64") {
      try {
        const cachedBinDir = await ensureCachedLinuxRelease(PKG.version);
        if (cachedBinDir) {
          const cachedBin = path.join(cachedBinDir, binary);
          if (isExecutable(cachedBin)) {
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
        `Install Docker (https://docs.docker.com/get-docker/) or build locally with:\n` +
        `  cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release && cmake --build build -j\n`
    );
    return 1;
  }

  const dockerArgs = buildDockerArgs(binary, args);
  return execBinary(dockerBin, dockerArgs, null);
}

module.exports = {
  buildDockerArgs,
  ensureCachedLinuxRelease,
  findLocalBinary,
  resolveTargetCommand,
  runCli,
  sha256File,
};
