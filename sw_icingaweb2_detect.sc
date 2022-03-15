if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111055" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-21 19:00:00 +0100 (Sat, 21 Nov 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Icinga Web 2 Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request
  to the server and attempts to extract the version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/icinga", "/icingaweb2", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/authentication/login";
	req = http_get_req( port: port, url: url, add_headers: make_array( "Cookie", "_chc=1" ) );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<title>Icinga Web 2 Login" ) || ContainsString( buf, "Icinga Web 2 &copy;" ) || ContainsString( buf, "var icinga = new Icinga" ) )){
		version = "unknown";
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		cpe = "cpe:/a:icinga:icingaweb2";
		set_kb_item( name: "www/" + port + "/icingaweb2", value: version );
		set_kb_item( name: "icingaweb2/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Icinga Web 2", version: version, install: install, concludedUrl: conclUrl, cpe: cpe ), port: port );
	}
}
exit( 0 );

