const pattern = new RegExp("^(a+)+$");
console.log(pattern.test(process.argv[2]));
