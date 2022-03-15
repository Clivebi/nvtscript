CPE = "cpe:/a:phpgroupware:phpgroupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16138" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2574" );
	script_bugtraq_id( 12082 );
	script_xref( name: "OSVDB", value: "7599" );
	script_xref( name: "OSVDB", value: "7600" );
	script_xref( name: "OSVDB", value: "7601" );
	script_xref( name: "OSVDB", value: "7602" );
	script_xref( name: "OSVDB", value: "7603" );
	script_xref( name: "OSVDB", value: "7604" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "PhpGroupWare index.php HTML injection vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "phpgroupware_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpGroupWare/installed" );
	script_tag( name: "solution", value: "Update to version 0.9.16 RC3 or newer" );
	script_tag( name: "summary", value: "The remote host seems to be running PhpGroupWare, a multi-user groupware
  suite written in PHP." );
	script_tag( name: "impact", value: "A malicious attacker may inject arbitrary HTML and script code using
  these form fields that may be incorporated into dynamically generated web content." );
	script_tag( name: "insight", value: "This version has been reported prone to HTML injection vulnerabilities
  through 'index.php'. These issues present themself due to a lack of
  sufficient input validation performed on form fields used by
  PHPGroupWare modules." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/phpsysinfo/inc/hook_admin.inc.php";
if(http_vuln_check( port: port, url: url, pattern: ".*Fatal error.* in <b>/.*" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

