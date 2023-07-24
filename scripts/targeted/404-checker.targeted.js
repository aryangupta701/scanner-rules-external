/**
 * @author Karthik UJ <karthik.uj@getastra.com>
 */

// Import Logger
var loggerManager = Java.type("org.apache.logging.log4j.LogManager");
var log = loggerManager.getLogger("404-Checker");

// Import constants
load(org.parosproxy.paros.Constant.getZapHome() + "astra-scripts/helper/constants.helper.js");

// Import some important classes
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var Model = Java.type("org.parosproxy.paros.model.Model");
var HistoryReference = Java.type("org.parosproxy.paros.model.HistoryReference");
var Control = Java.type("org.parosproxy.paros.control.Control");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

var session = Model.getSingleton().getSession();
var connectionParams = Model.getSingleton().getOptionsParam().getConnectionParam();
var extLoader = Control.getSingleton().getExtensionLoader();

function logger() {
	print("[" + this["zap.script.name"] + "] " + arguments[0]);
	log.info("[" + this["zap.script.name"] + "] " + arguments[0]);
}

/**
 * @param msg - HttpMessage
 */

function invokeWith(msg) {
    logger("scan started");

	logger("Testing if 404 is enabled on " + msg.getRequestHeader().getURI().toString());

    checkNotFoundEnabled(msg);
    
	logger("404 checker scan rule finished");

}

/**
 * @param msg - HttpMessage
 */
function checkNotFoundEnabled(msg) {
	var newReq = msg.cloneRequest();
	var uri = newReq.getRequestHeader().getURI();
	uri.setPath('/thisMostProbablyDoesNotExist');
	var sender = new HttpSender(connectionParams, true, 6);
	sender.sendAndReceive(newReq);
	ScriptVars.setGlobalCustomVar("404HttpMessage", msg.getResponseBody().toString());
	if (newReq.getResponseHeader().getStatusCode() == 404) {
        logger("404 check passed.");
		ScriptVars.setGlobalVar("is404Enabled", "True");
	} else {
        logger("404 check failed.");
        ScriptVars.setGlobalVar("is404Enabled", "False");
    }
}