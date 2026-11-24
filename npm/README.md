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

# 3. Auto-register Samurai MCP into all detected IDEs/CLIs (or a specific client)
# Supports: claude_code, claude_desktop, cursor, codex, gemini_cli, antigravity, windsurf, vscode, opencode, copilot_cli
npx -y samurai-net mcp setup --client all --yes
npx -y samurai-net mcp setup --client cursor --yes

# 4. Run a stateful HTTP/2 load test
npx -y samurai-net --worker l7 --target 127.0.0.1 --port 8080 --l7-protocol http2 --count 10000 --confirm
```

- **Linux:** `samurai-net` fetches the matching GitHub source archive on first run and **automatically compiles all binaries and workers natively on your machine** (`-DSAMURAI_NATIVE_ARCH=ON` for `-march=native` CPU SIMD, CUDA, DPDK, AF_XDP, `io_uring`, and DOCA) into `~/.cache/samurai/<ver>-native/` (or uses your local `build/` binaries if present).
- **Windows (PowerShell / CMD) & macOS (Docker Desktop):** `samurai-net` compiles natively for your host inside Docker (`SAMURAI_NATIVE_ARCH=ON`) — either by building `samurai:local-<ver>` locally or pulling the uncompiled `--ghcr` source image (`ghcr.io/mehmet8-dev/samurai:latest`) and compiling on first run into `-v samurai-build-cache:/var/cache/samurai`. `npx -y samurai-net mcp setup --client <id|all> --yes` (add `--ghcr` to use the GHCR source image) writes directly to native Windows/macOS paths (`%APPDATA%\Code\User\mcp.json`, `%APPDATA%\Claude\claude_desktop_config.json`, `%USERPROFILE%\.cursor\mcp.json`, `%USERPROFILE%\.gemini\antigravity\mcp_config.json`, `%USERPROFILE%\.codex\config.toml`, etc.), pre-warms the local native build, injects `--add-host host.docker.internal:host-gateway`, and uses `npx.cmd` automatically when `--npx` is requested. *(Pass `--no-build` during `mcp setup` to skip pre-warming, or set `SAMURAI_PREBUILT=1` on Linux only for native CLI tarballs.)*
