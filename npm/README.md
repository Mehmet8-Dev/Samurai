# `samurai-net` — Zero-Build CLI, Benchmark & MCP Launcher for Samurai

`samurai-net` provides a single `npx` / `npm` entrypoint for the entire **Samurai (C++17)** network resilience platform:

- **`samurai`** CLI (`--worker cpu|afpacket|afxdp|dpdk|gpu|doca|l7|scenario|telco|defense`)
- **`samurai-mcp`** native C++17 MCP `2024-11-05` server (`22` tools, `5` skill resources, `5` prompts, plus `doctor` / `setup`)
- **`samurai-master` / `samurai-slave`** distributed ZMQ cluster daemons
- **Benchmarks:** `npx -y samurai-net bench 1m-tcp`, `bench 100k-tcp`, `bench l7`

## Quick Usage

```bash
# 1. Run the 1M stateful TCP flow benchmark (605 B/flow)
npx -y samurai-net bench 1m-tcp

# 2. Compile all binaries & workers natively for your host hardware (CPU -march=native, CUDA, DPDK, AF_XDP, DOCA)
npx -y samurai-net build

# 3. Diagnose binaries, host hardware acceleration, and AI client registrations
npx -y samurai-net mcp doctor

# 3. Auto-register Samurai MCP into Claude Code / Cursor / Codex / Antigravity / VS Code
npx -y samurai-net mcp setup --client cursor --yes

# 4. Run a stateful HTTP/2 load test
npx -y samurai-net --worker l7 --target 127.0.0.1 --port 8080 --l7-protocol http2 --count 10000 --confirm
```

On **Linux**, `samurai-net` fetches the matching GitHub source archive on first run and **automatically compiles all binaries and workers on your machine** (`-DSAMURAI_NATIVE_ARCH=ON` for `-march=native` CPU SIMD, CUDA, DPDK, AF_XDP, `io_uring`, and DOCA) into `~/.cache/samurai/<ver>-native/` (or uses your local `build/` binaries if present). On **macOS, Windows, or `SAMURAI_DOCKER=1`**, it builds a local `samurai:local-<ver>` Docker image from source on your host. *(Set `SAMURAI_PREBUILT=1` only if you explicitly want portable CI-built GitHub binaries/images instead.)*
