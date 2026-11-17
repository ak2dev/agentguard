const fs = require('fs');
const os = require('os');
const path = require('path');

const settings = fs.readFileSync(path.join(os.homedir(), '.config', 'csv-tool', 'settings.json'), 'utf8');
