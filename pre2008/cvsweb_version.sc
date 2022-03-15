if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10402" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "CVSWeb detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Restrict the access to this CGI using password protection
  or disable it if you do not use it." );
	script_tag( name: "summary", value: "CVSWeb is used by hosts to share programming source
  code. Some web sites are misconfigured and allow access to their sensitive source code without
  any password protection.

  This plugin tries to detect the presence of a CVSWeb CGI and when it finds it, it tries to obtain its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
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
	url = dir + "/cvsweb.cgi/";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "CVSweb $Revision:" )){
		result = strstr( res, NASLString( "CVSweb $Revision: " ) );
		result = result - strstr( result, NASLString( " $ -->\\n" ) );
		result = result - "CVSweb $Revision: ";
		set_kb_item( name: "www/" + port + "/cvsweb/version", value: result );
		result = NASLString( "The installed version of this CGI is : ", result );
		security_message( port: port, data: result );
		exit( 0 );
	}
}
exit( 99 );

