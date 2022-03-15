if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105252" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-04-10 20:08:50 +0200 (Fri, 10 Apr 2015)" );
	script_name( "Novell ZENworks Control Center Detection" );
	script_tag( name: "summary", value: "The script sends a connection
request to the server and attempts to detect Novell ZENworks Control Center" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/zenworks", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/jsp/fw/internal/Login.jsp";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( IsMatchRegexp( buf, "<title> *Novell *ZENworks *Control *Center[^<]*</title>" ) || ContainsString( buf, "ZENworks Control Center requires" ) || ( ContainsString( buf, "Path=/zenworks/" ) && ContainsString( buf, "Server: Apache-Coyote" ) ) )){
		set_kb_item( name: "novell_zenworks_configuration_management/installed", value: TRUE );
		cpe = "cpe:/a:novell:zenworks_configuration_management";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Novell ZENworks Control Center", version: "unknown", install: install, cpe: cpe ), port: port );
		exit( 0 );
	}
}
exit( 0 );

