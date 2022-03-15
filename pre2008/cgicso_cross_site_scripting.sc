if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10780" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "CGIEmail's Cross Site Scripting Vulnerability (cgicso)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2001 SecurITeam" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Modify cgilib.c to contain a stripper function that will remove any HTML
  or JavaScript tags." );
	script_tag( name: "summary", value: "The remote web server contains the 'CGIEmail' CGI, a web based form to
  send emails which is vulnerable to a cross site scripting vulnerability.

  The remote version of this software contains a vulnerability caused by inadequate processing of queries
  by CGIEmail's cgicso  that results in a cross site scripting condition." );
	script_tag( name: "qod", value: "50" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/cgicso?query=<script>alert('foo')</script>";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\('foo'\\)</script>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

