const fs = require("node:fs");

const html = fs.readFileSync("pg_hostel_final.html", "utf8");
const script = html.match(/<script>([\s\S]*)<\/script>/);
new Function(script ? script[1] : "");
console.log("frontend-js-ok");
