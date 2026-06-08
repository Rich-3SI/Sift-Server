/**
 * Sift Rule Templates
 *
 * Pre-built security policies for common use cases. Reference them in sift.config.json
 * under the "policies" array by their id, e.g.:
 *
 *   { "policies": ["block-filesystem-writes", "redact-credentials"] }
 *
 * Templates are resolved before any custom rules and merged into the rule list.
 */

import { type SiftRule } from "./rules/index.js";

export interface RuleTemplate {
  id: string;
  name: string;
  description: string;
  category: "filesystem" | "database" | "network" | "credentials" | "code-execution" | "data" | "communication" | "git" | "browser" | "composite";
  tags: string[];
  rules: SiftRule[];
}

// ── Filesystem ────────────────────────────────────────────────────────────────

const BLOCK_FILESYSTEM_WRITES: RuleTemplate = {
  id: "block-filesystem-writes",
  name: "Block Filesystem Writes",
  description: "Prevents the agent from creating, modifying, or deleting any files.",
  category: "filesystem",
  tags: ["filesystem", "write", "destructive"],
  rules: [
    {
      id: "block-filesystem-writes/write_file",
      description: "Block write_file tool",
      match: `(toolName) => ["write_file", "create_file", "overwrite_file", "save_file"].includes(toolName)`,
      action: "block",
    },
    {
      id: "block-filesystem-writes/edit_file",
      description: "Block file editing tools",
      match: `(toolName) => ["edit_file", "patch_file", "replace_in_file", "str_replace_editor"].includes(toolName)`,
      action: "block",
    },
    {
      id: "block-filesystem-writes/delete_file",
      description: "Block file/directory deletion",
      match: `(toolName) => ["delete_file", "remove_file", "delete_directory", "rmdir", "rm"].includes(toolName)`,
      action: "block",
    },
    {
      id: "block-filesystem-writes/move_file",
      description: "Block file moves and renames",
      match: `(toolName) => ["move_file", "rename_file", "copy_file"].includes(toolName)`,
      action: "block",
    },
  ],
};

const BLOCK_FILESYSTEM_READS: RuleTemplate = {
  id: "block-filesystem-reads",
  name: "Block Filesystem Reads",
  description: "Prevents the agent from reading any files or listing directories.",
  category: "filesystem",
  tags: ["filesystem", "read", "privacy"],
  rules: [
    {
      id: "block-filesystem-reads/read_file",
      description: "Block read_file and similar tools",
      match: `(toolName) => ["read_file", "cat", "get_file_contents", "open_file"].includes(toolName)`,
      action: "block",
    },
    {
      id: "block-filesystem-reads/list_directory",
      description: "Block directory listing",
      match: `(toolName) => ["list_directory", "list_files", "ls", "readdir"].includes(toolName)`,
      action: "block",
    },
  ],
};

const BLOCK_ALL_FILESYSTEM: RuleTemplate = {
  id: "block-all-filesystem",
  name: "Block All Filesystem Access",
  description: "Full lockdown — no file reads, writes, or directory traversal.",
  category: "filesystem",
  tags: ["filesystem", "lockdown"],
  rules: [
    {
      id: "block-all-filesystem/any",
      description: "Block any tool that looks like a filesystem operation",
      match: `(toolName) => /^(read|write|edit|delete|remove|move|copy|rename|create|list|ls|cat|open|save|patch|str_replace|get_file|put_file|append|glob|find)_?(file|dir|directory|folder|path)?s?$/.test(toolName)`,
      action: "block",
    },
  ],
};

const SANDBOX_FILESYSTEM: RuleTemplate = {
  id: "sandbox-filesystem",
  name: "Sandbox Filesystem to /tmp",
  description: "Allows filesystem access only within /tmp — blocks any path outside it.",
  category: "filesystem",
  tags: ["filesystem", "sandbox"],
  rules: [
    {
      id: "sandbox-filesystem/path-check",
      description: "Block filesystem tools that target paths outside /tmp",
      match: `() => false`,
      condition: {
        tools: ["read_file", "write_file", "edit_file", "delete_file", "list_directory", "move_file", "create_file"],
        pathOutside: "/tmp",
      },
      action: "block",
    },
  ],
};

// ── Database ──────────────────────────────────────────────────────────────────

const BLOCK_SQL_MUTATIONS: RuleTemplate = {
  id: "block-sql-mutations",
  name: "Block SQL Mutations",
  description: "Prevents INSERT, UPDATE, DELETE, and MERGE queries.",
  category: "database",
  tags: ["database", "sql", "write", "destructive"],
  rules: [
    {
      id: "block-sql-mutations/dml",
      description: "Block DML SQL statements",
      match: `(toolName, input) => {
        const dbTools = ["execute_sql","run_query","query","sql","pg_query","mysql_query"];
        if (!dbTools.includes(toolName)) return false;
        const q = String(input?.query ?? input?.sql ?? "").toUpperCase().trim();
        return /^\\s*(INSERT|UPDATE|DELETE|REPLACE|MERGE|UPSERT)\\b/.test(q);
      }`,
      action: "block",
    },
  ],
};

const BLOCK_SQL_DDL: RuleTemplate = {
  id: "block-sql-ddl",
  name: "Block SQL Schema Changes",
  description: "Prevents DROP, CREATE, ALTER, and TRUNCATE statements that modify the schema.",
  category: "database",
  tags: ["database", "sql", "ddl", "destructive"],
  rules: [
    {
      id: "block-sql-ddl/ddl",
      description: "Block DDL SQL statements",
      match: `(toolName, input) => {
        const dbTools = ["execute_sql","run_query","query","sql","pg_query","mysql_query"];
        if (!dbTools.includes(toolName)) return false;
        const q = String(input?.query ?? input?.sql ?? "").toUpperCase().trim();
        return /^\\s*(DROP|CREATE|ALTER|TRUNCATE|RENAME)\\b/.test(q);
      }`,
      action: "block",
    },
  ],
};

const BLOCK_SQL_ALL_WRITES: RuleTemplate = {
  id: "block-sql-all-writes",
  name: "Block All SQL Writes",
  description: "Read-only database access — blocks all DDL and DML (INSERT, UPDATE, DELETE, DROP, etc.).",
  category: "database",
  tags: ["database", "sql", "readonly"],
  rules: [
    {
      id: "block-sql-all-writes/all",
      description: "Block any non-SELECT SQL statement",
      match: `(toolName, input) => {
        const dbTools = ["execute_sql","run_query","query","sql","pg_query","mysql_query","execute_query"];
        if (!dbTools.includes(toolName)) return false;
        const q = String(input?.query ?? input?.sql ?? "").toUpperCase().trim();
        return !/^\\s*SELECT\\b/.test(q) && q.length > 0;
      }`,
      action: "block",
    },
  ],
};

// ── Network ───────────────────────────────────────────────────────────────────

const BLOCK_NETWORK_REQUESTS: RuleTemplate = {
  id: "block-network-requests",
  name: "Block Network Requests",
  description: "Prevents the agent from making outbound HTTP/network calls.",
  category: "network",
  tags: ["network", "http", "exfiltration"],
  rules: [
    {
      id: "block-network-requests/http",
      description: "Block HTTP fetch and request tools",
      match: `(toolName) => ["fetch","http_request","web_fetch","curl","request","get_url","post_url","web_search"].includes(toolName)`,
      action: "block",
    },
  ],
};

// ── Credentials / Secrets ─────────────────────────────────────────────────────

const REDACT_CREDENTIALS: RuleTemplate = {
  id: "redact-credentials",
  name: "Redact Credentials in Logs",
  description: "Masks API keys, passwords, and tokens in audit logs — tool calls still proceed.",
  category: "credentials",
  tags: ["credentials", "secrets", "pii", "redact"],
  rules: [
    {
      id: "redact-credentials/any",
      description: "Redact any tool call that carries credential-like arguments",
      match: `(toolName, input) => {
        const s = JSON.stringify(input ?? {}).toLowerCase();
        return /api[_-]?key|password|passwd|secret|token|bearer|private[_-]?key|access[_-]?key/.test(s);
      }`,
      action: "redact",
    },
  ],
};

const BLOCK_SECRET_ENV_ACCESS: RuleTemplate = {
  id: "block-secret-env-access",
  name: "Block Secret Environment Variables",
  description: "Prevents reading environment variables that look like secrets.",
  category: "credentials",
  tags: ["credentials", "environment", "secrets"],
  rules: [
    {
      id: "block-secret-env-access/env",
      description: "Block access to env vars with secret-sounding names",
      match: `(toolName, input) => {
        const envTools = ["get_env","read_env","env","get_environment_variable"];
        if (!envTools.includes(toolName)) return false;
        const name = String(input?.name ?? input?.key ?? "").toUpperCase();
        return /SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS/.test(name);
      }`,
      action: "block",
    },
  ],
};

// ── Code Execution ────────────────────────────────────────────────────────────

const BLOCK_CODE_EXECUTION: RuleTemplate = {
  id: "block-code-execution",
  name: "Block Code Execution",
  description: "Prevents running shell commands, scripts, or arbitrary code.",
  category: "code-execution",
  tags: ["shell", "exec", "dangerous"],
  rules: [
    {
      id: "block-code-execution/shell",
      description: "Block shell and command execution tools",
      match: `(toolName) => ["execute","run","shell","bash","sh","exec","spawn","run_command","execute_command","run_script","eval","system","popen"].includes(toolName)`,
      action: "block",
    },
  ],
};

const BLOCK_PROCESS_MANAGEMENT: RuleTemplate = {
  id: "block-process-management",
  name: "Block Process Management",
  description: "Prevents the agent from killing, starting, or inspecting system processes.",
  category: "code-execution",
  tags: ["process", "system", "dangerous"],
  rules: [
    {
      id: "block-process-management/any",
      description: "Block process/system management tools",
      match: `(toolName) => ["kill_process","start_process","list_processes","force_terminate","get_process","ps"].includes(toolName)`,
      action: "block",
    },
  ],
};

// ── Data Exfiltration ─────────────────────────────────────────────────────────

const BLOCK_CLIPBOARD: RuleTemplate = {
  id: "block-clipboard",
  name: "Block Clipboard Access",
  description: "Prevents reading from or writing to the system clipboard.",
  category: "data",
  tags: ["clipboard", "exfiltration"],
  rules: [
    {
      id: "block-clipboard/any",
      description: "Block clipboard tools",
      match: `(toolName) => ["read_clipboard","write_clipboard","get_clipboard","set_clipboard","clipboard_read","clipboard_write"].includes(toolName)`,
      action: "block",
    },
  ],
};

// ── Sensitive File Paths ──────────────────────────────────────────────────────

const BLOCK_SENSITIVE_PATHS: RuleTemplate = {
  id: "block-sensitive-paths",
  name: "Block Sensitive File Paths",
  description: "Prevents accessing ~/.ssh, ~/.aws, .env files, /etc/passwd, key files, and other sensitive locations.",
  category: "filesystem",
  tags: ["filesystem", "security", "secrets", "ssh", "aws"],
  rules: [
    {
      id: "block-sensitive-paths/check",
      description: "Block filesystem tools targeting sensitive paths",
      match: `(toolName, input) => {
        const fsTools = ["read_file","write_file","edit_file","delete_file","list_directory","move_file","create_file","open_file","cat","get_file_contents","read_text_file","read_media_file","read_multiple_files"];
        if (!fsTools.includes(toolName)) return false;
        const args = input ?? {};
        const morePaths = Array.isArray(args.paths) ? args.paths : [];
        const paths = [args.path, args.file_path, args.source, args.destination, ...morePaths].filter((p) => typeof p === "string");
        const sensitive = /(\\.ssh|\\/.aws|\\/.gnupg|\\/.config\\/gcloud|\\.env($|\\.)|credentials\\.json|secrets\\.ya?ml|\\/etc\\/passwd|\\/etc\\/shadow|\\.pem$|\\.key$|\\.p12$|\\.pfx$|\\.keystore|id_rsa|id_ed25519|\\.git\\/config|\\.npmrc|\\.pypirc|\\.docker\\/config)/;
        return paths.some((p) => sensitive.test(p));
      }`,
      action: "block",
    },
  ],
};

const BLOCK_CREDENTIAL_FILES: RuleTemplate = {
  id: "block-credential-files",
  name: "Block Credential File Reads",
  description: "Blocks reading .env, credentials.json, key files, and other secret-bearing files.",
  category: "credentials",
  tags: ["credentials", "secrets", "files"],
  rules: [
    {
      id: "block-credential-files/read",
      description: "Block reading credential files",
      match: `(toolName, input) => {
        const readTools = ["read_file","cat","get_file_contents","open_file","read_text_file","read_media_file","read_multiple_files"];
        if (!readTools.includes(toolName)) return false;
        const args = input ?? {};
        const morePaths = Array.isArray(args.paths) ? args.paths : [];
        const paths = [args.path, args.file_path, ...morePaths].filter((p) => typeof p === "string");
        const credFile = /(\\.env($|\\.)|credentials\\.json|secrets\\.ya?ml|service[_-]?account\\.json|\\.pem$|\\.key$|\\.p12$|\\.pfx$|id_rsa|id_ed25519|\\.npmrc|\\.pypirc|\\.netrc|\\.pgpass)/;
        return paths.some((p) => credFile.test(p));
      }`,
      action: "block",
    },
  ],
};

// ── Communication ─────────────────────────────────────────────────────────────

const BLOCK_EMAIL_MESSAGING: RuleTemplate = {
  id: "block-email-messaging",
  name: "Block Email & Messaging",
  description: "Prevents the agent from sending emails, Slack messages, or other outbound communications.",
  category: "communication",
  tags: ["email", "slack", "messaging", "exfiltration"],
  rules: [
    {
      id: "block-email-messaging/email",
      description: "Block email sending tools",
      match: `(toolName) => ["gmail_create_draft","gmail_send","send_email","send_mail","create_draft","reply_to_email","forward_email","compose_email"].includes(toolName)`,
      action: "block",
    },
    {
      id: "block-email-messaging/slack",
      description: "Block Slack/chat messaging tools",
      match: `(toolName) => ["send_message","post_message","send_slack","reply_to_thread","reply_to_toolbar_thread","edit_toolbar_message","chat_post_message","send_notification"].includes(toolName)`,
      action: "block",
    },
  ],
};

// ── PII Redaction ─────────────────────────────────────────────────────────────

const REDACT_ALL_PII: RuleTemplate = {
  id: "redact-all-pii",
  name: "Redact PII in All Tool Calls",
  description: "Automatically redacts SSNs, credit cards, phone numbers, and email addresses in all tool call inputs and outputs.",
  category: "data",
  tags: ["pii", "redact", "privacy", "compliance"],
  rules: [
    {
      id: "redact-all-pii/always",
      description: "Redact PII in every tool call",
      match: `() => true`,
      action: "redact",
    },
  ],
};

// ── Git / Deployment ──────────────────────────────────────────────────────────

const BLOCK_GIT_PUSH: RuleTemplate = {
  id: "block-git-push",
  name: "Block Git Push & Publish",
  description: "Allows local git operations but blocks pushing to remotes, publishing packages, or deploying.",
  category: "git",
  tags: ["git", "deploy", "publish", "safety"],
  rules: [
    {
      id: "block-git-push/shell-push",
      description: "Block shell commands that push or publish",
      match: `(toolName, input) => {
        const shellTools = ["execute","run","shell","bash","sh","exec","run_command","execute_command","start_process"];
        if (!shellTools.includes(toolName)) return false;
        const cmd = String(input?.command ?? input?.cmd ?? "").toLowerCase();
        return /\\bgit\\s+push\\b|\\bgit\\s+push\\s|\\bnpm\\s+publish\\b|\\byarn\\s+publish\\b|\\bgh\\s+pr\\s+create\\b|\\bgh\\s+release\\b|\\bdeploy\\b|\\bheroku\\b|\\bvercel\\s+deploy\\b|\\baws\\s+s3\\s+(cp|sync|mv)\\b/.test(cmd);
      }`,
      action: "block",
    },
    {
      id: "block-git-push/deploy-tools",
      description: "Block deployment and publish tools",
      match: `(toolName) => ["deploy","deploy_to_vercel","publish","push","git_push","npm_publish","create_release"].includes(toolName)`,
      action: "block",
    },
  ],
};

// ── Browser ───────────────────────────────────────────────────────────────────

const BLOCK_BROWSER_NAVIGATION: RuleTemplate = {
  id: "block-browser-navigation",
  name: "Block Browser Navigation",
  description: "Prevents navigating to arbitrary URLs via browser control MCP servers. Blocks potential data exfiltration through browser tools.",
  category: "browser",
  tags: ["browser", "navigation", "exfiltration"],
  rules: [
    {
      id: "block-browser-navigation/navigate",
      description: "Block browser navigation tools",
      match: `(toolName) => ["navigate","open_url","go_to_url","browse","web_fetch","web_fetch_vercel_url","open_tab","tabs_create_mcp"].includes(toolName)`,
      action: "block",
    },
    {
      id: "block-browser-navigation/js-exec",
      description: "Block arbitrary JavaScript execution in browser",
      match: `(toolName) => ["execute_javascript","javascript_tool","eval","preview_eval"].includes(toolName)`,
      action: "block",
    },
  ],
};

// ── Read-Only Mode ────────────────────────────────────────────────────────────

const READ_ONLY_MODE: RuleTemplate = {
  id: "read-only-mode",
  name: "Read-Only Mode",
  description: "Comprehensive observe-only policy — blocks all writes across filesystem, database, network, processes, and communication.",
  category: "composite",
  tags: ["readonly", "lockdown", "safety", "observe"],
  rules: [
    {
      id: "read-only-mode/filesystem-writes",
      description: "Block all filesystem write operations",
      match: `(toolName) => ["write_file","create_file","overwrite_file","save_file","edit_file","patch_file","replace_in_file","str_replace_editor","delete_file","remove_file","delete_directory","rmdir","rm","move_file","rename_file","copy_file","create_directory","mkdir","append_file","write_pdf"].includes(toolName)`,
      action: "block",
    },
    {
      id: "read-only-mode/sql-writes",
      description: "Block all non-SELECT SQL",
      match: `(toolName, input) => {
        const dbTools = ["execute_sql","run_query","query","sql","pg_query","mysql_query","execute_query","apply_migration"];
        if (!dbTools.includes(toolName)) return false;
        const q = String(input?.query ?? input?.sql ?? "").toUpperCase().trim();
        return !/^\\s*SELECT\\b/.test(q) && q.length > 0;
      }`,
      action: "block",
    },
    {
      id: "read-only-mode/network",
      description: "Block outbound HTTP requests",
      match: `(toolName) => ["fetch","http_request","web_fetch","curl","request","post_url","web_search"].includes(toolName)`,
      action: "block",
    },
    {
      id: "read-only-mode/processes",
      description: "Block process management",
      match: `(toolName) => ["kill_process","start_process","force_terminate","execute","run","shell","bash","sh","exec","run_command","execute_command"].includes(toolName)`,
      action: "block",
    },
    {
      id: "read-only-mode/communication",
      description: "Block email and messaging",
      match: `(toolName) => ["gmail_create_draft","gmail_send","send_email","send_message","post_message","send_slack","reply_to_thread","deploy","deploy_to_vercel","git_push","publish"].includes(toolName)`,
      action: "block",
    },
  ],
};

// ── Dangerous Shell Commands ──────────────────────────────────────────────────

const BLOCK_DANGEROUS_SHELL: RuleTemplate = {
  id: "block-dangerous-shell",
  name: "Block Dangerous Shell Commands",
  description: "Allows shell execution but blocks destructive patterns like rm -rf, chmod, mkfs, dd, curl|sh, and similar.",
  category: "code-execution",
  tags: ["shell", "destructive", "safety"],
  rules: [
    {
      id: "block-dangerous-shell/destructive",
      description: "Block dangerous shell command patterns",
      match: `(toolName, input) => {
        const shellTools = ["execute","run","shell","bash","sh","exec","run_command","execute_command","start_process","spawn"];
        if (!shellTools.includes(toolName)) return false;
        const cmd = String(input?.command ?? input?.cmd ?? "");
        return /\\brm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive|--force)|\\brm\\s+-rf\\b|\\bchmod\\s|\\bchown\\s|\\bmkfs\\b|\\bdd\\s+if=|\\b(curl|wget)\\s.*\\|\\s*(sh|bash|zsh)|\\bformat\\b|\\bfdisk\\b|\\b>\\/dev\\/|\\bshutdown\\b|\\breboot\\b|\\bsystemctl\\s+(stop|disable|mask)|\\bkill\\s+-9|\\bkillall\\b|\\bpkill\\b|\\bnc\\s+-l|\\biptables\\b/.test(cmd);
      }`,
      action: "block",
    },
  ],
};

// ── Sandbox to Project Directory ──────────────────────────────────────────────

const SANDBOX_PROJECT_DIR: RuleTemplate = {
  id: "sandbox-project-dir",
  name: "Sandbox to Working Directory",
  description: "Allows filesystem access only within the current working directory — blocks any absolute path that traverses outside it or uses ../.",
  category: "filesystem",
  tags: ["filesystem", "sandbox", "project"],
  rules: [
    {
      id: "sandbox-project-dir/path-check",
      description: "Block filesystem tools targeting paths outside the working directory",
      match: `(toolName, input) => {
        const fsTools = ["read_file","write_file","edit_file","delete_file","list_directory","move_file","create_file","open_file","cat","get_file_contents","read_text_file","read_multiple_files"];
        if (!fsTools.includes(toolName)) return false;
        const args = input ?? {};
        const paths = [args.path, args.file_path, args.source, args.destination].filter((p) => typeof p === "string");
        return paths.some((p) => {
          if (p.includes("..")) return true;
          if (p.startsWith("/") || p.startsWith("~")) return true;
          return false;
        });
      }`,
      action: "block",
    },
  ],
};

// ── Blast Radius Preset ───────────────────────────────────────────────────────

const CONSERVATIVE_BLAST_RADIUS: RuleTemplate = {
  id: "conservative-blast-radius",
  name: "Conservative Blast Radius",
  description: "Limits destructive operations to 3 per session — blocks delete, drop, truncate, and similar tools after the limit.",
  category: "data",
  tags: ["blast-radius", "destructive", "safety"],
  rules: [
    {
      id: "conservative-blast-radius/warn",
      description: "Flag destructive tool calls for audit (the built-in BlastRadiusLimiter enforces the cap)",
      match: `(toolName) => ["delete_file","remove_file","drop_table","delete_row","truncate","rm","unlink","purge","wipe","delete_database","drop_collection","clear_table","destroy","force_terminate","kill_process"].includes(toolName.toLowerCase())`,
      action: "allow",
    },
  ],
};

// ── Package Installation ─────────────────────────────────────────────────────

const BLOCK_PACKAGE_INSTALL: RuleTemplate = {
  id: "block-package-install",
  name: "Block Package Installation",
  description: "Prevents agents from installing packages via npm, pip, cargo, gem, etc. Guards against supply-chain attacks from untrusted dependencies.",
  category: "code-execution",
  tags: ["packages", "supply-chain", "npm", "pip", "safety"],
  rules: [
    {
      id: "block-package-install/shell",
      description: "Block shell commands that install packages",
      match: `(toolName, input) => {
        const shellTools = ["execute","run","shell","bash","sh","exec","run_command","execute_command","start_process","spawn"];
        if (!shellTools.includes(toolName)) return false;
        const cmd = String(input?.command ?? input?.cmd ?? "").toLowerCase();
        return /\\bnpm\\s+(install|i|add|ci)\\b|\\byarn\\s+(add|install)\\b|\\bpnpm\\s+(add|install|i)\\b|\\bbun\\s+(add|install|i)\\b|\\bpip\\s+install\\b|\\bpip3\\s+install\\b|\\bcargo\\s+(add|install)\\b|\\bgem\\s+install\\b|\\bgo\\s+(get|install)\\b|\\bbrew\\s+install\\b|\\bapt(-get)?\\s+install\\b|\\bcomposer\\s+(require|install)\\b/.test(cmd);
      }`,
      action: "block",
    },
  ],
};

// ── Docker Operations ────────────────────────────────────────────────────────

const BLOCK_DOCKER_OPERATIONS: RuleTemplate = {
  id: "block-docker-operations",
  name: "Block Docker & Container Operations",
  description: "Prevents agents from creating containers, pulling images, or managing Docker infrastructure.",
  category: "code-execution",
  tags: ["docker", "containers", "infrastructure", "safety"],
  rules: [
    {
      id: "block-docker-operations/shell",
      description: "Block shell commands that manage containers",
      match: `(toolName, input) => {
        const shellTools = ["execute","run","shell","bash","sh","exec","run_command","execute_command","start_process","spawn"];
        if (!shellTools.includes(toolName)) return false;
        const cmd = String(input?.command ?? input?.cmd ?? "").toLowerCase();
        return /\\bdocker\\s+(run|build|pull|push|exec|compose|create|start|stop|rm|rmi|volume|network|swarm|stack)\\b|\\bdocker-compose\\s|\\bpodman\\s+(run|build|pull|push|exec|create)\\b|\\bkubectl\\s+(apply|create|delete|exec|run|scale|rollout)\\b/.test(cmd);
      }`,
      action: "block",
    },
  ],
};

// ── Cloud CLI ────────────────────────────────────────────────────────────────

const BLOCK_CLOUD_CLI: RuleTemplate = {
  id: "block-cloud-cli",
  name: "Block Cloud CLI Commands",
  description: "Prevents agents from modifying cloud infrastructure via AWS, GCP, or Azure CLI tools.",
  category: "code-execution",
  tags: ["cloud", "aws", "gcp", "azure", "infrastructure", "safety"],
  rules: [
    {
      id: "block-cloud-cli/shell",
      description: "Block cloud provider CLI commands",
      match: `(toolName, input) => {
        const shellTools = ["execute","run","shell","bash","sh","exec","run_command","execute_command","start_process","spawn"];
        if (!shellTools.includes(toolName)) return false;
        const cmd = String(input?.command ?? input?.cmd ?? "").toLowerCase();
        return /\\baws\\s+(s3|ec2|iam|lambda|rds|ecs|eks|cloudformation|sqs|sns|dynamodb|sts)\\b|\\bgcloud\\s+(compute|storage|iam|run|functions|sql|container|app)\\b|\\baz\\s+(vm|storage|group|aks|webapp|functionapp|sql|keyvault|network|role)\\b|\\bterraform\\s+(apply|destroy|import)\\b|\\bpulumi\\s+(up|destroy|preview)\\b/.test(cmd);
      }`,
      action: "block",
    },
  ],
};

// ── SSH / Remote Operations ──────────────────────────────────────────────────

const BLOCK_SSH_REMOTE: RuleTemplate = {
  id: "block-ssh-remote",
  name: "Block SSH & Remote Operations",
  description: "Prevents agents from opening SSH connections, SCP transfers, or remote command execution. Guards against lateral movement.",
  category: "network",
  tags: ["ssh", "remote", "lateral-movement", "safety"],
  rules: [
    {
      id: "block-ssh-remote/shell",
      description: "Block shell commands that initiate remote connections",
      match: `(toolName, input) => {
        const shellTools = ["execute","run","shell","bash","sh","exec","run_command","execute_command","start_process","spawn"];
        if (!shellTools.includes(toolName)) return false;
        const cmd = String(input?.command ?? input?.cmd ?? "").toLowerCase();
        return /\\bssh\\s|\\bscp\\s|\\bsftp\\s|\\brsync\\s.*:|\\bsshpass\\s|\\bssh-copy-id\\b|\\btelnet\\s|\\bftp\\s|\\brsh\\s|\\brlogin\\s|\\brexec\\s/.test(cmd);
      }`,
      action: "block",
    },
  ],
};

// ── Audit-Only Mode ──────────────────────────────────────────────────────────

const AUDIT_ONLY_MODE: RuleTemplate = {
  id: "audit-only-mode",
  name: "Audit-Only Mode",
  description: "Logs every tool call without blocking anything. Ideal for onboarding teams who want visibility before enforcing policies.",
  category: "composite",
  tags: ["audit", "observe", "onboarding", "visibility"],
  rules: [
    {
      id: "audit-only-mode/log-all",
      description: "Log all tool calls for audit",
      match: `() => true`,
      action: "allow",
    },
  ],
};

// ── Block Config Modification ────────────────────────────────────────────────

const BLOCK_CONFIG_MODIFICATION: RuleTemplate = {
  id: "block-config-modification",
  name: "Block Config & Settings Modification",
  description: "Prevents agents from modifying MCP configs, IDE settings, shell profiles, or dotfiles. Stops agents from removing Sift or reconfiguring their own tool access.",
  category: "filesystem",
  tags: ["config", "settings", "self-protection", "dotfiles", "safety"],
  rules: [
    {
      id: "block-config-modification/dotfiles",
      description: "Block writes to config files and dotfiles",
      match: `(toolName, input) => {
        const writeTools = ["write_file","create_file","overwrite_file","save_file","edit_file","patch_file","replace_in_file","str_replace_editor","delete_file","remove_file","move_file","rename_file","append_file"];
        if (!writeTools.includes(toolName)) return false;
        const path = String(input?.path ?? input?.file_path ?? input?.destination ?? "").toLowerCase();
        return /claude_desktop_config\\.json|\\.claude\\.json|\\.cursor\\/mcp\\.json|mcp_config\\.json|mcp\\.json|\\.sift\\/|\\.zshrc|\\.bashrc|\\.bash_profile|\\.profile|\\.gitconfig|\\.npmrc|\\.env$|\\.env\\.local|settings\\.json|keybindings\\.json|forge\\.config/.test(path);
      }`,
      action: "block",
    },
    {
      id: "block-config-modification/shell",
      description: "Block shell commands that modify configs",
      match: `(toolName, input) => {
        const shellTools = ["execute","run","shell","bash","sh","exec","run_command","execute_command","start_process","spawn"];
        if (!shellTools.includes(toolName)) return false;
        const cmd = String(input?.command ?? input?.cmd ?? "").toLowerCase();
        return /echo\\s.*>>?\\s*~?\\/?\\.?(zshrc|bashrc|bash_profile|profile|gitconfig|npmrc|env)|sed\\s+-i.*\\.(zshrc|bashrc|profile|gitconfig)|rm\\s.*\\.sift|rm\\s.*claude_desktop_config/.test(cmd);
      }`,
      action: "block",
    },
    {
      id: "block-config-modification/set-config",
      description: "Block MCP server config modification tools",
      match: `(toolName) => ["set_config","set_config_value","update_config","modify_settings"].includes(toolName)`,
      action: "block",
    },
  ],
};

// ── Rate Limit Tool Calls ────────────────────────────────────────────────────

const RATE_LIMIT_TOOL_CALLS: RuleTemplate = {
  id: "rate-limit-tool-calls",
  name: "Rate-Limit Tool Calls",
  description: "Flags all tool calls for audit tracking. Combined with the built-in rate limiter, detects runaway agents that exceed normal usage patterns.",
  category: "data",
  tags: ["rate-limit", "runaway", "monitoring", "safety"],
  rules: [
    {
      id: "rate-limit-tool-calls/flag-all",
      description: "Flag every tool call for rate tracking",
      match: `() => true`,
      action: "allow",
    },
  ],
};

// ── Registry ──────────────────────────────────────────────────────────────────

export const TEMPLATES: RuleTemplate[] = [
  // Filesystem
  BLOCK_FILESYSTEM_WRITES,
  BLOCK_FILESYSTEM_READS,
  BLOCK_ALL_FILESYSTEM,
  SANDBOX_FILESYSTEM,
  SANDBOX_PROJECT_DIR,
  BLOCK_SENSITIVE_PATHS,
  // Database
  BLOCK_SQL_MUTATIONS,
  BLOCK_SQL_DDL,
  BLOCK_SQL_ALL_WRITES,
  // Network
  BLOCK_NETWORK_REQUESTS,
  // Credentials
  REDACT_CREDENTIALS,
  BLOCK_SECRET_ENV_ACCESS,
  BLOCK_CREDENTIAL_FILES,
  // Code execution
  BLOCK_CODE_EXECUTION,
  BLOCK_PROCESS_MANAGEMENT,
  BLOCK_DANGEROUS_SHELL,
  // Data
  BLOCK_CLIPBOARD,
  REDACT_ALL_PII,
  CONSERVATIVE_BLAST_RADIUS,
  // Communication
  BLOCK_EMAIL_MESSAGING,
  // Git / Deployment
  BLOCK_GIT_PUSH,
  // Browser
  BLOCK_BROWSER_NAVIGATION,
  // Supply chain / Infrastructure
  BLOCK_PACKAGE_INSTALL,
  BLOCK_DOCKER_OPERATIONS,
  BLOCK_CLOUD_CLI,
  BLOCK_SSH_REMOTE,
  // Config protection
  BLOCK_CONFIG_MODIFICATION,
  // Monitoring
  AUDIT_ONLY_MODE,
  RATE_LIMIT_TOOL_CALLS,
  // Composite
  READ_ONLY_MODE,
];

const TEMPLATE_MAP = new Map<string, RuleTemplate>(TEMPLATES.map((t) => [t.id, t]));

/**
 * Resolve a list of policy ids into SiftRule[].
 * Unknown ids are logged and skipped.
 */
export function resolveTemplates(policyIds: string[]): SiftRule[] {
  const rules: SiftRule[] = [];
  for (const id of policyIds) {
    const template = TEMPLATE_MAP.get(id);
    if (!template) {
      process.stderr.write(`[Sift] Unknown policy template: "${id}" — skipped.\n`);
      continue;
    }
    // Built-in template rules are trusted — bypass sandbox validation
    rules.push(...template.rules.map((r) => ({ ...r, trusted: true })));
  }
  return rules;
}

/** List all available templates. */
export function listTemplates(): RuleTemplate[] {
  return TEMPLATES;
}
