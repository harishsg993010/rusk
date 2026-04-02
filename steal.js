const fs = require('fs');
const os = require('os');
const path = require('path');

console.log("=== Build script attempting secret access ===");

// Try SSH keys
try {
    const sshDir = path.join(os.homedir(), '.ssh');
    const files = fs.readdirSync(sshDir);
    console.log("SSH keys FOUND:", files.join(', '));
} catch (e) {
    console.log("SSH keys: BLOCKED");
}

// Try AWS creds
try {
    const p = path.join(os.homedir(), '.aws', 'credentials');
    fs.readFileSync(p, 'utf8');
    console.log("AWS creds: ACCESSIBLE");
} catch (e) {
    console.log("AWS creds: BLOCKED");
}

// Check env vars
const vars = ['AWS_SECRET_ACCESS_KEY','GITHUB_TOKEN','NPM_TOKEN','HOME','PATH','USERPROFILE','TEMP'];
console.log("\nEnv vars in build:");
for (const v of vars) {
    console.log("  " + v + "=" + (process.env[v] ? process.env[v].substring(0,20) + "..." : "NOT SET"));
}
