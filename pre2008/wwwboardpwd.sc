if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10321" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 649, 12453 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-1999-0953" );
	script_name( "wwwboard passwd.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 1999 Jonathan Provencher" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/1998_3/0746.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/1999-q3/0993.html" );
	script_tag( name: "solution", value: "Configure the wwwadmin.pl script to change the name and location of
  'passwd.txt'." );
	script_tag( name: "summary", value: "This WWWBoard board system comes with a password file (passwd.txt) installed
  next to the file 'wwwboard.html'." );
	script_tag( name: "impact", value: "An attacker may obtain the content of this file and decode the password to
  modify the remote www board." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
	url = dir + "/wwwboard.html";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(ContainsString( res, "wwwboard.pl" )){
		url = dir + "/passwd.txt";
		if(http_vuln_check( port: port, url: url, pattern: "^[A-Za-z0-9]*:[a-zA-Z0-9-_.]$" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

