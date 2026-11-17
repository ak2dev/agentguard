const name = process.argv[2];
const plugin = require(name);
plugin.run();
