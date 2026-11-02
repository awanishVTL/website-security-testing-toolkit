/**
 * Logger utility with clean ANSI colors and structured formatting.
 */

const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  bgRed: '\x1b[41m\x1b[37m',
  bgYellow: '\x1b[43m\x1b[30m',
  bgGreen: '\x1b[42m\x1b[30m'
};

const logger = {
  info(msg, ...args) {
    console.log(`${colors.blue}[INFO]${colors.reset} ${msg}`, ...args);
  },
  success(msg, ...args) {
    console.log(`${colors.green}[PASS]${colors.reset} ${msg}`, ...args);
  },
  warn(msg, ...args) {
    console.log(`${colors.yellow}[WARN]${colors.reset} ${msg}`, ...args);
  },
  error(msg, ...args) {
    console.error(`${colors.red}[FAIL]${colors.reset} ${msg}`, ...args);
  },
  finding(severity, title, endpoint) {
    const color = severity === 'Critical' || severity === 'High' ? colors.red
      : severity === 'Medium' ? colors.yellow
      : colors.cyan;
    console.log(`  ${color}[${severity.toUpperCase()}]${colors.reset} ${title} ${colors.gray}--> ${endpoint}${colors.reset}`);
  },
  header(title) {
    console.log(`\n${colors.bold}${colors.cyan}=== ${title.toUpperCase()} ===${colors.reset}`);
  },
  divider() {
    console.log(`${colors.gray}------------------------------------------------------------${colors.reset}`);
  }
};

module.exports = logger;
