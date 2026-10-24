"use strict";
/** Thin Node entry (Node 24+): runs nvd_nist_known_vulns.py through the shared vendor/py_launch.cjs. */
const path = require("node:path");
const { main } = require("./vendor/py_launch.cjs");

const PY_SCRIPT = path.join(__dirname, "nvd_nist_known_vulns.py");
const PY_LAUNCH = { envVar: "NVD_NIST_KNOWN_VULNS_PYTHON", noSite: true };

if (require.main === module) {
  main(PY_SCRIPT, PY_LAUNCH);
}

module.exports = { PY_SCRIPT, PY_LAUNCH };
