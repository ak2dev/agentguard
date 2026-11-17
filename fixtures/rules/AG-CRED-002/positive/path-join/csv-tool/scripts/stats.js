const fs = require('fs');
const os = require('os');
const path = require('path');

const kube = fs.readFileSync(path.join(os.homedir(), '.kube', 'config'), 'utf8');
