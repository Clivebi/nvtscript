if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106327" );
	script_version( "$Revision: 11702 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-01 09:31:38 +0200 (Mon, 01 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-10-05 15:37:40 +0700 (Wed, 05 Oct 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-1289" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Prime Infrastructure Authentication Bypass API Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_pis_web_detect.sc" );
	script_mandatory_keys( "cisco/pis/http/port" );
	script_tag( name: "summary", value: "A vulnerability in the application programming interface (API) of Cisco
Prime Infrastructure could allow an unauthenticated, remote attacker to access and control the API resources." );
	script_tag( name: "insight", value: "The vulnerability is due to improper input validation of HTTP requests for
unauthenticated URIs. An attacker could exploit this vulnerability by sending a crafted HTTP request to the
affected URIs." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability could allow the attacker to
upload malicious code to the application server or read unauthorized management data, such as credentials of
devices managed by Cisco Prime Infrastructure." );
	script_tag( name: "affected", value: "Cisco Prime Infrastructure software versions 1.2 through version 3.0." );
	script_tag( name: "solution", value: "Upgrade to version 2.2.3 Update 4, 3.0.3 Update 2, or later" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160629-piauthbypass" );
	script_xref( name: "URL", value: "http://www.security-assessment.com/files/documents/advisory/Cisco-Prime-Infrastructure-Release.pdf" );
	script_tag( name: "vuldetect", value: "Tries to get the version over the REST API." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_kb_item( "cisco/pis/http/port" )){
	exit( 0 );
}
host = http_host_name( port: port );
req = "GET /webacs/api/v1/op/info/version?_docs HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "X-HTTP-Method-Override: get\r\n" + "Content-Type: application/json\r\n" + "Connection: close\r\n" + "Content-Length: 0\r\n\r\n";
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.. 200" ) && ContainsString( res, "<versionInfoDTO>" )){
	version = eregmatch( pattern: "<result>.*</result>", string: res );
	report = "It was possible to get the version information through the REST API.\\n\\nResult:\\n\\n" + version[0] + "\\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

