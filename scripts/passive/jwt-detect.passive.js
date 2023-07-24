/**
 * @author Divyansh Jain <divyansh.jain@getastra.com>
 */

// Import constants.
load(org.parosproxy.paros.Constant.getZapHome() + "astra-scripts/helper/constants.helper.js");
// Import Extra Meta Data Helper
load(org.parosproxy.paros.Constant.getZapHome() + "astra-scripts/helper/otherInfo.helper.js");
// Plugin ID
var pluginId = 1204686;

// Import Logger
var LoggerManager = Java.type("org.apache.logging.log4j.LogManager");
var log = LoggerManager.getLogger("hardcoded-jwt-detect");

// HasMap for alertTags
var HashMap = Java.type('java.util.HashMap');

function logger() {
  log.info("[" + this["zap.script.name"] + "] " + arguments[0]);
}

function scan(ps, msg, src) {
    logger("scan started");

  // Change Meta Data
  var metaData = new MetaData();
  metaData.setBounty = 0;
  metaData.setBountyDescription = "";
  metaData.setBountyReferenceUrl = "";
  metaData.setCvss31Numeric = 5.8;
  metaData.setCvss31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N";

  // Alert Tags
  var alertTags = new HashMap();
  alertTags.put("OWASP_2021_A05", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/");

  var url = msg.getRequestHeader().getURI().toString();
  var js_reg = /(.*.js$)|(.*.js\?)/i
  var contentType = msg.getResponseHeader().getHeader("Content-Type");
  var body = msg.getResponseBody().toString();
  var jwt_reg = /(ey[A-Za-z0-9-_]*\.ey[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*)/i;

  // Detect JWT in Js file
  if (contentType === "application/javascript" || js_reg.test(url) || contentType === "text/javascript") {
    if (jwt_reg.test(body)) {
      ps.newAlert()
        .setPluginId(pluginId)
        .setRisk(RISK_MEDIUM)
        .setConfidence(CONFIDENCE_MEDIUM)
        .setName('JWT Token Found in JS File')
        .setDescription('Hardcoded JWT token in JS file. This can allow attacker to gain unauthorized access to assets.')
        .setEvidence(body.match(jwt_reg).join())
        .setOtherInfo(metaData.json)
        .setSolution('Hardcoded JWTs in publicly accessible source code is not recommended, please remove it.')
        .setCweId(200)
        .setWascId(13)
        .setTags(alertTags)
        .raise();
    }
  }

  // Detect jwt in url
  if (jwt_reg.test(url)) {
    ps.newAlert()
      .setPluginId(pluginId)
      .setRisk(RISK_LOW)
      .setConfidence(CONFIDENCE_MEDIUM)
      .setName('JWT Token Found in URL')
      .setDescription('URLs are often logged in browser history and server logs, making them visible to attackers therefore sensitive information like JWTs should not be sent in URL.')
      .setEvidence(url.match(jwt_reg).join())
      .setOtherInfo(metaData.json)
      .setSolution('We recommend removing JWTs from URLs and storing them in a more secure manner.')
      .setCweId(200)
      .setWascId(13)
      .setTags(alertTags)
      .raise();
  }
}