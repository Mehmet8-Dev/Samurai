"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CLIENT_SPECS = [
  { id: "claude_code", displayName: "Claude Code", format: "json_mcp_servers", supportsProjectScope: true },
  { id: "claude_desktop", displayName: "Claude Desktop", format: "json_mcp_servers", supportsProjectScope: false },
  { id: "cursor", displayName: "Cursor", format: "json_mcp_servers", supportsProjectScope: true },
  { id: "codex", displayName: "Codex CLI", format: "toml_codex", supportsProjectScope: false },
  { id: "gemini_cli", displayName: "Gemini CLI", format: "json_mcp_servers", supportsProjectScope: true },
  { id: "antigravity", displayName: "Antigravity", format: "json_mcp_servers", supportsProjectScope: false },
  { id: "windsurf", displayName: "Windsurf", format: "json_mcp_servers", supportsProjectScope: false },
  { id: "vscode", displayName: "VS Code", format: "json_servers_stdio", supportsProjectScope: true },
  { id: "opencode", displayName: "OpenCode", format: "json_opencode", supportsProjectScope: true },
  { id: "copilot_cli", displayName: "GitHub Copilot CLI", format: "json_mcp_servers", supportsProjectScope: false },
];

const CLIENT_ALIASES = {
  claude: "claude_code",
  "claude-code": "claude_code",
  claude_code: "claude_code",
  "claude-desktop": "claude_desktop",
  claude_desktop: "claude_desktop",
  cursor: "cursor",
  codex: "codex",
  "codex-cli": "codex",
  gemini: "gemini_cli",
  "gemini-cli": "gemini_cli",
  gemini_cli: "gemini_cli",
  antigravity: "antigravity",
  windsurf: "windsurf",
  vscode: "vscode",
  "vs-code": "vscode",
  opencode: "opencode",
  "open-code": "opencode",
  copilot: "copilot_cli",
  "copilot-cli": "copilot_cli",
  copilot_cli: "copilot_cli",
};

function normalizeClientId(raw) {
  const key = String(raw || "").trim().toLowerCase();
  return CLIENT_ALIASES[key] || "";
}

function normalizeHostOs(raw, platform = process.platform) {
  const s = String(raw || "").trim().toLowerCase();
  if (s === "win" || s === "win32" || s === "windows") return "windows";
  if (s === "mac" || s === "macos" || s === "darwin") return "macos";
  if (s === "linux") return "linux";
  if (platform === "win32") return "windows";
  if (platform === "darwin") return "macos";
  return "linux";
}

function resolveClientConfigPath(spec, opts = {}) {
  const hostOs = normalizeHostOs(opts.hostOs, opts.platform || process.platform);
  const home = opts.home || os.homedir();
  const project = opts.project || process.cwd();
  const nativePath = (opts.platform || process.platform) === "win32" ? path.win32 : path.posix;
  const appData =
    opts.appData ||
    (hostOs === "windows"
      ? process.env.APPDATA || nativePath.join(home, "AppData", "Roaming")
      : "");
  // Keep POSIX separators when callers pass POSIX override directories (e.g., Linux unit tests simulating Windows)
  // while honoring Windows drive/UNC paths and real win32 execution.
  const usesWinPath =
    /^[A-Za-z]:/.test(home) ||
    home.startsWith("\\\\") ||
    /^[A-Za-z]:/.test(appData) ||
    appData.startsWith("\\\\") ||
    (!opts.home && !opts.appData && !opts.project && hostOs === "windows" && (opts.platform || process.platform) === "win32");
  const pathImpl = usesWinPath ? path.win32 : path.posix;
  const scope = opts.scope || "user";
  const id = spec.id;

  if (scope === "project" && spec.supportsProjectScope) {
    if (id === "claude_code") return pathImpl.join(project, ".mcp.json");
    if (id === "cursor") return pathImpl.join(project, ".cursor", "mcp.json");
    if (id === "gemini_cli") return pathImpl.join(project, ".gemini", "settings.json");
    if (id === "vscode") return pathImpl.join(project, ".vscode", "mcp.json");
    if (id === "opencode") return pathImpl.join(project, "opencode.json");
  }

  if (id === "claude_code") return pathImpl.join(home, ".claude.json");
  if (id === "claude_desktop") {
    if (hostOs === "windows") return pathImpl.join(appData, "Claude", "claude_desktop_config.json");
    if (hostOs === "macos") return pathImpl.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
    return pathImpl.join(home, ".config", "Claude", "claude_desktop_config.json");
  }
  if (id === "cursor") return pathImpl.join(home, ".cursor", "mcp.json");
  if (id === "codex") return pathImpl.join(home, ".codex", "config.toml");
  if (id === "gemini_cli") return pathImpl.join(home, ".gemini", "settings.json");
  if (id === "antigravity") return pathImpl.join(home, ".gemini", "antigravity", "mcp_config.json");
  if (id === "windsurf") return pathImpl.join(home, ".codeium", "windsurf", "mcp_config.json");
  if (id === "vscode") {
    if (hostOs === "windows") return pathImpl.join(appData, "Code", "User", "mcp.json");
    if (hostOs === "macos") return pathImpl.join(home, "Library", "Application Support", "Code", "User", "mcp.json");
    return pathImpl.join(home, ".config", "Code", "User", "mcp.json");
  }
  if (id === "opencode") return pathImpl.join(home, ".config", "opencode", "opencode.json");
  if (id === "copilot_cli") return pathImpl.join(home, ".copilot", "mcp-config.json");
  return "";
}

function buildServerSpec({ transportMode, imageTag, hostOs, mcpBin }) {
  if (transportMode === "npx") {
    return {
      command: hostOs === "windows" ? "npx.cmd" : "npx",
      args: ["-y", "-p", "samurai-net", "samurai-mcp"],
    };
  }
  if (transportMode === "docker") {
    const args = ["run", "-i", "--rm", "-v", "samurai-build-cache:/var/cache/samurai"];
    if (hostOs === "linux") {
      args.push("--network", "host");
    } else {
      args.push("--add-host", "host.docker.internal:host-gateway");
    }
    args.push(imageTag, "samurai_mcp");
    return { command: "docker", args };
  }
  return { command: mcpBin, args: [] };
}

function formatServerEntry(format, spec) {
  if (format === "json_opencode") {
    return {
      type: "local",
      command: [spec.command, ...spec.args],
      enabled: true,
    };
  }
  if (format === "json_servers_stdio") {
    return {
      type: "stdio",
      command: spec.command,
      args: spec.args,
    };
  }
  return {
    command: spec.command,
    args: spec.args,
  };
}

function jsonContainerKey(format) {
  if (format === "json_servers_stdio") return "servers";
  if (format === "json_opencode") return "mcp";
  return "mcpServers";
}

function tomlQuote(s) {
  return `"${String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function buildCodexTomlBlock(spec) {
  const argsList = spec.args.map(tomlQuote).join(", ");
  return `[mcp_servers.samurai]\ncommand = ${tomlQuote(spec.command)}\nargs = [${argsList}]\n`;
}

function upsertCodexToml(existing, block) {
  const lines = existing ? existing.split(/\r?\n/) : [];
  const out = [];
  let skipping = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("[")) {
      if (trimmed === "[mcp_servers.samurai]" || trimmed.startsWith("[mcp_servers.samurai.")) {
        skipping = true;
        continue;
      }
      skipping = false;
    }
    if (!skipping) out.push(line);
  }
  while (out.length > 0 && out[out.length - 1] === "") out.pop();
  if (out.length > 0) out.push("");
  out.push(block.trimEnd());
  return `${out.join("\n")}\n`;
}

function isRegisteredInContent(format, content) {
  if (!content) return false;
  if (format === "toml_codex") {
    return content.includes("[mcp_servers.samurai]");
  }
  try {
    const parsed = JSON.parse(content);
    const key = jsonContainerKey(format);
    return Boolean(parsed && typeof parsed === "object" && parsed[key] && parsed[key].samurai);
  } catch {
    return false;
  }
}

function executeSetup(opts) {
  const hostOs = normalizeHostOs(opts.hostOs, opts.platform || process.platform);
  const scope = opts.scope || "user";
  if (scope !== "user" && scope !== "project") {
    return { ok: false, exitCode: 2, report: { ok: false, error: "scope must be 'user' or 'project'" } };
  }
  if (opts.docker && opts.npx) {
    return {
      ok: false,
      exitCode: 2,
      report: { ok: false, error: "Cannot combine --docker and --npx; choose one transport mode." },
    };
  }

  const normClient = normalizeClientId(opts.client);
  const spec = CLIENT_SPECS.find((c) => c.id === normClient);
  if (!spec) {
    return {
      ok: false,
      exitCode: 2,
      report: {
        ok: false,
        error: `Unknown client '${opts.client}'. Supported: ${CLIENT_SPECS.map((c) => c.id).join(", ")}, all`,
      },
    };
  }

  const mcpBin = opts.binaryOverride || "";
  let transportMode = "docker";
  if (opts.npx) {
    transportMode = "npx";
  } else if (opts.docker || hostOs !== "linux" || !mcpBin) {
    transportMode = "docker";
  } else {
    transportMode = "native";
  }

  const configPath = resolveClientConfigPath(spec, {
    hostOs,
    scope,
    home: opts.homeOverride,
    project: opts.projectOverride,
    appData: opts.appDataOverride,
  });
  const serverSpec = buildServerSpec({
    transportMode,
    imageTag: opts.imageTag,
    hostOs,
    mcpBin,
  });
  const proposedEntry =
    spec.format === "toml_codex"
      ? buildCodexTomlBlock(serverSpec)
      : formatServerEntry(spec.format, serverSpec);

  const exists = fs.existsSync(configPath);
  let existingText = "";
  if (exists) {
    existingText = fs.readFileSync(configPath, "utf8");
  }

  let newContent = "";
  if (spec.format === "toml_codex") {
    newContent = upsertCodexToml(existingText, proposedEntry);
  } else {
    let doc = {};
    if (exists && existingText.trim().length > 0) {
      try {
        doc = JSON.parse(existingText);
        if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
          throw new Error("root is not a JSON object");
        }
      } catch (err) {
        return {
          ok: false,
          exitCode: 2,
          report: {
            ok: false,
            error: `Existing config is not valid JSON (refusing to overwrite): ${configPath} (${err.message})`,
          },
        };
      }
    }
    const containerKey = jsonContainerKey(spec.format);
    if (!doc[containerKey] || typeof doc[containerKey] !== "object") {
      doc[containerKey] = {};
    }
    doc[containerKey].samurai = proposedEntry;
    newContent = `${JSON.stringify(doc, null, 2)}\n`;
  }

  const apply = Boolean(opts.yes);
  const backupPath = `${configPath}.bak`;
  let backupCreated = false;
  if (apply) {
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    if (exists) {
      fs.copyFileSync(configPath, backupPath);
      backupCreated = true;
    }
    fs.writeFileSync(configPath, newContent, "utf8");
  }

  return {
    ok: true,
    exitCode: 0,
    report: {
      ok: true,
      applied: apply,
      host_os: hostOs,
      client: spec.id,
      display_name: spec.displayName,
      scope,
      transport_mode: transportMode,
      image: transportMode === "docker" ? opts.imageTag : "",
      config_path: configPath,
      config_existed: exists,
      backup_path: exists ? backupPath : "",
      backup_created: backupCreated,
      proposed_entry: proposedEntry,
      next_step: apply
        ? `Restart or reconnect ${spec.displayName} so the samurai MCP tools become active.`
        : "Re-run with --yes to write the proposed configuration.",
    },
  };
}

function buildDoctorReport(opts = {}, helpers = {}) {
  const hostOs = normalizeHostOs(opts.hostOs, opts.platform || process.platform);
  const dockerBin = helpers.findInPath ? helpers.findInPath("docker") : null;
  const localMcp = helpers.findLocalBinary ? helpers.findLocalBinary("samurai_mcp") : null;
  const localSamurai = helpers.findLocalBinary ? helpers.findLocalBinary("samurai") : null;

  let filterClient = "";
  let filterErr = "";
  if (opts.client) {
    filterClient = normalizeClientId(opts.client);
    if (!filterClient) {
      filterErr = `Unknown client '${opts.client}'. Supported: ${CLIENT_SPECS.map((c) => c.id).join(", ")}`;
    }
  }

  const clients = [];
  for (const spec of CLIENT_SPECS) {
    if (filterClient && spec.id !== filterClient) continue;
    const cfgPath = resolveClientConfigPath(spec, {
      hostOs,
      scope: "user",
      home: opts.homeOverride,
      project: opts.projectOverride,
      appData: opts.appDataOverride,
    });
    const exists = fs.existsSync(cfgPath);
    const content = exists ? fs.readFileSync(cfgPath, "utf8") : "";
    const registered = isRegisteredInContent(spec.format, content);
    clients.push({
      client: spec.id,
      display_name: spec.displayName,
      config_path: cfgPath,
      config_exists: exists,
      registered,
    });
  }

  const report = {
    platform: hostOs,
    arch: process.arch,
    ready: Boolean(localMcp || dockerBin),
    core_binaries: {
      samurai: { available: Boolean(localSamurai), path: localSamurai || "" },
      samurai_mcp: { available: Boolean(localMcp), path: localMcp || "" },
    },
    prerequisites: {
      docker_available: Boolean(dockerBin),
      docker_path: dockerBin || "",
    },
    clients,
  };
  if (filterErr) report.client_filter_error = filterErr;
  return report;
}

function printSetupUsage() {
  process.stdout.write(
    "Usage:\n" +
      "  samurai-net mcp doctor [--client <id>] [--host-os <linux|macos|windows>] [--json]\n" +
      "  samurai-net mcp setup --client <id|all> [--scope <user|project>] [--docker | --npx] [--ghcr] [--image <tag>] [--host-os <linux|macos|windows>] [--no-build] [--yes] [--json]\n\n" +
      `Supported clients: ${CLIENT_SPECS.map((c) => c.id).join(", ")}, all\n`
  );
}

async function runHostMcpConfigCmd(sub, args, ctx) {
  if (sub === "doctor") {
    const opts = { client: "", json: false, hostOs: "" };
    for (let i = 0; i < args.length; ++i) {
      const a = args[i];
      if (a === "-h" || a === "--help") {
        printSetupUsage();
        return 0;
      } else if (a === "--json") {
        opts.json = true;
      } else if (a === "--client" && i + 1 < args.length) {
        opts.client = args[++i];
      } else if (a === "--host-os" && i + 1 < args.length) {
        opts.hostOs = args[++i];
      } else {
        process.stderr.write(`samurai mcp doctor: unknown option '${a}'\n`);
        return 2;
      }
    }
    const report = buildDoctorReport(opts, ctx);
    if (opts.json) {
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    } else {
      process.stdout.write(`Samurai MCP Doctor (${report.platform}/${report.arch})\n`);
      if (report.client_filter_error) {
        process.stderr.write(`error: ${report.client_filter_error}\n`);
        return 2;
      }
      process.stdout.write(
        `Docker: ${report.prerequisites.docker_available ? `available (${report.prerequisites.docker_path})` : "not found"}\n` +
          `Native samurai_mcp: ${report.core_binaries.samurai_mcp.available ? report.core_binaries.samurai_mcp.path : "not built (Docker or npx available)"}\n\n` +
          "MCP Clients:\n"
      );
      for (const c of report.clients) {
        process.stdout.write(
          `  ${c.client.padEnd(16)} [${c.registered ? "REGISTERED    " : "NOT REGISTERED"}] ${c.config_path}\n`
        );
      }
    }
    return report.ready ? 0 : 1;
  }

  // sub === "setup"
  const opts = {
    client: "",
    scope: "user",
    imageTag: ctx.defaultImageTag,
    docker: false,
    npx: false,
    yes: false,
    json: false,
    noBuild: false,
    hostOs: "",
  };
  for (let i = 0; i < args.length; ++i) {
    const a = args[i];
    if (a === "-h" || a === "--help") {
      printSetupUsage();
      return 0;
    } else if (a === "--client" && i + 1 < args.length) {
      opts.client = args[++i];
    } else if (a === "--all") {
      opts.client = "all";
    } else if (a === "--scope" && i + 1 < args.length) {
      opts.scope = args[++i];
    } else if (a === "--image" && i + 1 < args.length) {
      opts.imageTag = args[++i];
    } else if (a === "--ghcr") {
      opts.docker = true;
      opts.imageTag = "ghcr.io/mehmet8-dev/samurai:latest";
    } else if (a === "--host-os" && i + 1 < args.length) {
      opts.hostOs = args[++i];
    } else if (a === "--docker") {
      opts.docker = true;
    } else if (a === "--npx") {
      opts.npx = true;
    } else if (a === "--yes" || a === "-y") {
      opts.yes = true;
    } else if (a === "--json") {
      opts.json = true;
    } else if (a === "--no-build") {
      opts.noBuild = true;
    } else {
      process.stderr.write(`samurai mcp setup: unknown option '${a}'\n`);
      return 2;
    }
  }

  if (!opts.client) {
    if (opts.json) {
      process.stdout.write(`${JSON.stringify({ ok: false, error: "--client is required" })}\n`);
    } else {
      printSetupUsage();
    }
    return 2;
  }

  const hostOs = normalizeHostOs(opts.hostOs);
  const localMcp = ctx.findLocalBinary ? ctx.findLocalBinary("samurai_mcp") : null;
  opts.binaryOverride = localMcp || "";

  let targetClients = [opts.client];
  if (String(opts.client).trim().toLowerCase() === "all") {
    // Register every client whose parent config directory already exists (or whose config already exists).
    targetClients = [];
    for (const spec of CLIENT_SPECS) {
      const cfgPath = resolveClientConfigPath(spec, { hostOs, scope: opts.scope });
      const parentDir = path.dirname(cfgPath);
      if (fs.existsSync(cfgPath) || fs.existsSync(parentDir)) {
        targetClients.push(spec.id);
      }
    }
    if (targetClients.length === 0) {
      targetClients = ["claude_code", "cursor", "vscode"];
    }
  }

  const results = [];
  let overallOk = true;
  let exitCode = 0;
  let needsDockerBuild = false;

  for (const cid of targetClients) {
    const res = executeSetup({ ...opts, client: cid });
    results.push(res.report);
    if (!res.ok) {
      overallOk = false;
      exitCode = res.exitCode || 1;
    } else if (res.report.applied && res.report.transport_mode === "docker") {
      needsDockerBuild = true;
    }
  }

  if (needsDockerBuild && !opts.noBuild && ctx.ensureLocalDockerImage) {
    const dockerBin = ctx.findInPath ? ctx.findInPath("docker") : null;
    if (dockerBin) {
      try {
        await ctx.ensureLocalDockerImage(dockerBin, opts.imageTag);
      } catch (err) {
        process.stderr.write(
          `[samurai-net] Warning: MCP config written, but local Docker image build failed: ${err.message}\n` +
            `Run 'docker build -t ${opts.imageTag} .' manually before starting your IDE.\n`
        );
      }
    } else {
      process.stderr.write(
        "[samurai-net] Note: 'docker' was not found in PATH yet. Install Docker Desktop so your IDE can launch the Samurai MCP container.\n"
      );
    }
  }

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(results.length === 1 ? results[0] : { ok: overallOk, results }, null, 2)}\n`);
  } else {
    for (const r of results) {
      if (!r.ok) {
        process.stderr.write(`samurai setup: ${r.error}\n`);
        continue;
      }
      process.stdout.write(
        `Samurai MCP Setup (${r.display_name})\n` +
          `  Status:     ${r.applied ? "APPLIED" : "NOT WRITTEN (pass --yes to apply)"}\n` +
          `  Host OS:    ${r.host_os}\n` +
          `  Mode:       ${r.transport_mode}${r.image ? ` (${r.image})` : ""}\n` +
          `  Config:     ${r.config_path}\n` +
          (r.config_existed ? `  Backup:     ${r.backup_path}\n` : "") +
          `  Next step:  ${r.next_step}\n`
      );
    }
  }
  return exitCode;
}

module.exports = {
  CLIENT_SPECS,
  buildDoctorReport,
  buildServerSpec,
  executeSetup,
  normalizeClientId,
  normalizeHostOs,
  resolveClientConfigPath,
  runHostMcpConfigCmd,
};
