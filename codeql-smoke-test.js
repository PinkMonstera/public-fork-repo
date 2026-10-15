/**
 * CodeQL smoke-test fixtures (intentional insecure patterns).
 *
 * Purpose: verify a CodeQL workflow can build a DB, run queries, and report alerts.
 * Do NOT copy these patterns into production code.
 *
 * Expected: github/codeql-action with languages: javascript-typescript
 * should raise findings (e.g. command injection, path traversal, XSS).
 *
 * Place this file in the repo under something like:
 *   test/security/codeql-smoke-test.js
 * then push or run the CodeQL workflow via workflow_dispatch.
 */

const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const express = require("express");

const app = express();

// --- Command injection (js/command-line-injection / similar) ---
app.get("/run", (req, res) => {
  // User-controlled input passed directly to a shell command.
  const cmd = "ls " + req.query.dir;
  exec(cmd, (err, stdout) => {
    if (err) {
      res.status(500).send(String(err));
      return;
    }
    res.send(stdout);
  });
});

// --- Path traversal (js/path-injection / similar) ---
app.get("/read", (req, res) => {
  // User-controlled path joined without sanitization.
  const target = path.join(__dirname, "files", req.query.name);
  const data = fs.readFileSync(target, "utf8");
  res.send(data);
});

// --- Reflected XSS (js/reflected-xss / similar) ---
app.get("/greet", (req, res) => {
  // Untrusted input written into an HTML response without encoding.
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

// --- Unsafe deserialization-style eval (js/eval-injection / similar) ---
app.post("/calc", express.text(), (req, res) => {
  // Evaluating attacker-controlled text.
  const result = eval(req.body);
  res.json({ result });
});

app.listen(3000, () => {
  console.log("codeql-smoke-test listening on :3000");
});
