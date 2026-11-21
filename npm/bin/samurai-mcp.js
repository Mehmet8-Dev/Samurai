#!/usr/bin/env node
"use strict";

const { runCli } = require("../lib/launcher");

runCli("samurai_mcp", process.argv.slice(2)).then((code) => process.exit(code));
