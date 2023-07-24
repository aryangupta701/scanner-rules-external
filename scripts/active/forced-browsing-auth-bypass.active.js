/**
 * @author Karthik UJ <karthik.uj@getastra.com>
 */

/**
 * In this method the attacker tries to browse a URL which generally should require authentication. If the website is vulnerable then it will give access to the attacker without proper verification.
 * To automate this we will need:
 * 1. Either a list of general paths for authenticated domains like '/admin' or customer specific authenticated domains.
 * 2. Then we need to check if that path is accessible without needing any authentication. 
 * 3. Then send and check responses.
 * 
 * Tested on: https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality
 * 
 * Complexity: MEDIUM
 */

// Import constants
load(org.parosproxy.paros.Constant.getZapHome() + "astra-scripts/helper/constants.helper.js");

// Import extra meta data
load(org.parosproxy.paros.Constant.getZapHome() + "astra-scripts/helper/otherInfo.helper.js");

// Import Logger
var LoggerManager = Java.type("org.apache.logging.log4j.LogManager");
var log = LoggerManager.getLogger("forced-browsing-auth-bypass");

// HasMap for alertTags
var HashMap = Java.type('java.util.HashMap');

// Import some important classes
var Model = Java.type("org.parosproxy.paros.model.Model")
var connectionParams = Model.getSingleton().getOptionsParam().getConnectionParam();
var URI = Java.type("org.apache.commons.httpclient.URI")
var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender")
var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader")
var HttpRequestBody = Java.type("org.zaproxy.zap.network.HttpRequestBody")
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var HtmlParameter = Java.type("org.parosproxy.paros.network.HtmlParameter");
var Control = Java.type("org.parosproxy.paros.control.Control");
var ExtensionAlert = Java.type("org.zaproxy.zap.extension.alert.ExtensionAlert");
var Alert = Java.type("org.parosproxy.paros.core.scanner.Alert");
var HistoryReference = Java.type("org.parosproxy.paros.model.HistoryReference");
var Control = Java.type("org.parosproxy.paros.control.Control");
var MalformedURLException = Java.type("java.net.MalformedURLException");
var URL = Java.type("java.net.URL");
var TreeSet = Java.type("java.util.TreeSet");
var extLoader = Control.getSingleton().getExtensionLoader();
var session = Model.getSingleton().getSession();
var connectionParams = Model.getSingleton().getOptionsParam().getConnectionParam();

function logger() {
	// print("[" + this["zap.script.name"] + "] " + arguments[0]);
	log.info("[" + this["zap.script.name"] + "] " + arguments[0]);
}

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */

function raiseAlert(pluginIdRef, alertRisk, alertConfidence, alertName, msg, url, alertEvidence) {

    var pluginId = 1204654;
    var metaData = new MetaData();
	metaData.setBounty = 750;
	metaData.setBountyDescription = "For a similar vulnerability, New Relic paid over $750 bug bounty.";
	metaData.setBountyReferenceUrl = "https://hackerone.com/reports/255685";
	metaData.setCvss31Numeric = 9.1;
	metaData.setCvss31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N";
    metaData.setFetchFromAlert = true;


	var alertDesc = "Forced browsing is a technique in which the attacker does not follow the intended flow of the web aplication and instead tries to browse URLs which generally should have some sort of authentication or authorization. Using this technique the attacker can try to find unsecured and unprotected pages which should've been available only after proper authentication.";
	var alertSol = "Always check if the user is authorized to view confidential pages.";
	var alertRef = "https://owasp.org/www-community/attacks/Forced_browsing";
	var cweId = 425; // Direct Request ('Forced Browsing')
	var wascId = 2; // Insufficient Authorization
	var alertTags = new HashMap();
    alertTags.put("OWASP_2021_A07", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/");
	alertTags.put("OWASP_2017_A02", "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication.html");
	alertTags.put("ISO-27001", "https://advisera.com/27001academy/blog/2018/04/24/how-to-use-open-web-application-security-project-owasp-for-iso-27001/");
	alertTags.put("GDPR", "https://gdpr.eu/checklist/");
	alertTags.put("HIPAA", "https://www.hipaajournal.com/hipaa-compliance-checklist/");
	alertTags.put("PCI-DSS", "https://www.pcidssguide.com/pci-web-application-security-requirements/");


    var extensionAlert = extLoader.getExtension(ExtensionAlert.NAME);
    var alert = new Alert(pluginId, alertRisk, alertConfidence, alertName);
    var ref = new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, msg);
    alert.setMessage(msg);
    alert.setUri(url);
    alert.setDescription(alertDesc);
    alert.setCweId(cweId);
    alert.setWascId(wascId);
    alert.setSolution(alertSol);
    alert.setReference(alertRef);
    alert.setOtherInfo(metaData.json);
    alert.setTags(alertTags);
    alert.setEvidence(alertEvidence);
    alert.setAlertRef(pluginId.toString() + '-' + pluginIdRef);
    extensionAlert.alertFound(alert, ref);
}

 function scanNode(as, msg) {
	// Debugging can be done using println like this
	logger('scan called for url=' + msg.getRequestHeader().getURI().toString());

	// Check if the scan was stopped before performing lengthy tasks
	if (as.isStop()) {
		return
	}

	// send normal request
	var valid_request = msg.cloneRequest();
	as.sendAndReceive(valid_request, false, false);
	
	// response content type should be either of this: xml, html or json
	if (!valid_request.getResponseHeader().isXml() && !valid_request.getResponseHeader().isJson() 
		&& !valid_request.getResponseHeader().isHtml()) {
			// exit the scan because content type is neither of xml,html and json
			return;
		}

	// check if auth is happening based on auth headers
	auth_header_keywords = ["Authentication", "Auth", "Authorization", "auth"]
	for (var i=0; i<auth_header_keywords.length; i++) {
		try {
			var valid_keyword_value = msg.getRequestHeader().getHeader(auth_header_keywords[i]);
			if (valid_keyword_value && !valid_keyword_value.isEmpty()) {
				logger(auth_header_keywords[i] + " header Found");
				// auth keyword present, now prepare request
				var new_auth_request = msg.cloneRequest();
				new_auth_request.setRequestHeader(valid_request.getRequestHeader().toString().replace(valid_keyword_value, ""));
				new_auth_request.getRequestHeader().setContentLength(new_auth_request.getRequestBody().length());
				logger("Sending Request without AUTH header");
				as.sendAndReceive(new_auth_request, false, false);
				logger("Sending Request without AUTH header");
				as.sendAndReceive(new_auth_request, false, false);
				// test condition for forced browsing
				testConidition(valid_request, new_auth_request);
				return
			}
		} catch (err) {
			logger(err);
		} 
	}

	// check if auth is happening based on cookie (only option left)
	var get_cookie = msg.getRequestHeader().getHeader('Cookie')
	
	if (get_cookie) {
	// check if session cookie is available or not
		var session_cookie_reg = /session|token|auth|sess|sid|login|logged|uid|userid/i
		if (!session_cookie_reg.test(get_cookie)) {
			return ;
		}
		logger("Probable session cookie Found");
		// session cookie present, now prepare request
		var new_auth_with_cookie_request = msg.cloneRequest();
		new_auth_with_cookie_request.setRequestHeader(valid_request.getRequestHeader().toString().replace(get_cookie,""));
		new_auth_with_cookie_request.getRequestHeader().setContentLength(new_auth_with_cookie_request.getRequestBody().length());
		logger("Sending Request without Cookie");
		as.sendAndReceive(new_auth_with_cookie_request, false, false);
		testConidition(valid_request, new_auth_with_cookie_request);
	}
	return
}

function testConidition(authenticated_response, unauthenticated_response) {
	// reject 404 and 200 having same status code
	if (ScriptVars.getGlobalVar("is404Enabled")) {
		logger("Site is responding with same status code for 200 and 404 as well")
		return ;
	}
	// reject 4** and 5**
	var reject_status = /[4-5][0-9][0-9]/
	if (reject_status.test(authenticated_response.getRequestHeader().getStatusCode().toString()) || reject_status.test(unauthenticated_response.getRequestHeader().getStatusCode().toString())) {
		logger("rejected 4** and 5** based status code")
		return;
	}
	// reject if both responses don't match
	if (authenticated_response.getResponseBody().toString() == unauthenticated_response.getResponseBody().toString()) {
		logger("Response of authenticated & un-authenticated request matched");
		// reject the response if both responses have 302 status code
		if (authenticated_response.getResponseHeader().getStatusCode() == 302 && unauthenticated_response.getResponseHeader().getStatusCode() == 302) {
			logger("both responses have 302 status code");
			return;
		}
		blacklist_regex = /login|about|contact|policy|blog|article|log-in|sign|logout|career|contact|legal|product|feature|pricing|copyright|resource/i
		// reject the response if uri match blacklist keyword
		if (blacklist_regex.test(unauthenticated_response.getRequestHeader().getURI())) {
			logger("uri matched blacklist keyword");
			return;
		}
		// reject the response if response-body match keyword
		blacklist_body_regex = /last-updated|today|enable javascript|last updated/i
		if (blacklist_body_regex.test(unauthenticated_response.getResponseBody())) {
			logger("response-body matched blacklist keyword");
			return;
		}
		// raise the high severity alert with high confidence if uri match the whitelisted keyword
		whitelist_regex = /setting|preference|admin|dashboard|upload|profile|backup|config|log|member|private|db|users|auth|edit/i
		if (whitelist_regex.test(unauthenticated_response.getRequestHeader().getURI())) {
			logger("Forced browsing Found with High Severity");
			var alertName = "Forced Browsing Found (Broken Access Control)"
			raiseAlert(
				"1",
				RISK_HIGH,
				CONFIDENCE_LOW,
				alertName,
				unauthenticated_response,
				unauthenticated_response.getRequestHeader().getURI().toString(),
				"");
			return;
		}
		// raise the info severity alert with low confidence 
		// Mention Recommendation in alert name
		logger("Raising alert for Forced browsing Recommendation");
		var alertName = "Recommendation to Check for Forced Browsing(Broken Access Control) On Following End-points"
		raiseAlert(
			"2",
			RISK_INFO,
			CONFIDENCE_LOW,
			alertName,
			unauthenticated_response,
			unauthenticated_response.getRequestHeader().getURI().toString(),
			"");
	} else {
		logger("Response of authenticated & un-authenticated request didn't matched");
	}
	return;
}