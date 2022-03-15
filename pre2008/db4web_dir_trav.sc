if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11182" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 5723 );
	script_cve_id( "CVE-2002-1483" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "DB4Web directory traversal" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software." );
	script_tag( name: "summary", value: "It is possible to read any file on your
  system through the DB4Web software." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
cgis = http_get_kb_cgis( port: port, host: host );
if(isnull( cgis )){
	exit( 0 );
}
win_files = traversal_files( "windows" );
lin_files = traversal_files( "linux" );
for cgi in cgis {
	if( ContainsString( cgi, "/db4web_c.exe/" ) ){
		end = strstr( cgi, "/db4web_c.exe/" );
		dir = cgi - end;
		for pattern in keys( win_files ) {
			file = win_files[pattern];
			file = str_replace( string: file, find: "/", replace: "%5C" );
			url = strcat( dir, "/db4web_c.exe/c%3A%5C", file );
			if(http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
	else {
		if(ContainsString( dir, "/db4web_c/" )){
			end = strstr( cgi, "/db4web_c/" );
			dir = cgi - end;
			for pattern in keys( lin_files ) {
				file = lin_files[pattern];
				url = strcat( dir, "/db4web_c//", file );
				if(http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE )){
					report = http_report_vuln_url( port: port, url: url );
					security_message( port: port, data: report );
					exit( 0 );
				}
			}
		}
	}
}
exit( 99 );

