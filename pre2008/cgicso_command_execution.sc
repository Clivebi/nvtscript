if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10779" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2002-1652" );
	script_bugtraq_id( 6141 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CGIEmail's CGICso (Send CSO via CGI) Command Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2001 SecurITeam" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "The server can be compromised by executing commands as the web server's
  running user (usually 'nobody')." );
	script_tag( name: "solution", value: "Modify cgicso.h to contain a strict setting of your finger host.

  Example:

  Define the following in cgicso.h:

  #define CGI_CSO_HARDCODE

  #define CGI_CSO_FINGERHOST 'localhost'" );
	script_tag( name: "summary", value: "The remote host seems to be vulnerable to a security problem in
  CGIEmail (cgicso).  The vulnerability is caused by inadequate processing of queries by CGIEmail's
  cgicso and results in a command execution vulnerability." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/cgicso?query=AAA";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( buf, "400 Required field missing: fingerhost" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

