if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106436" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-07 15:34:03 +0700 (Wed, 07 Dec 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Piwigo Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Piwigo

  The script sends a connection request to the server and attempts to detect the presence of Piwigo and to
  extract its version" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/piwigo", "/Piwigo", "/photos", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	req = http_get_req( port: port, url: dir + "/index.php", user_agent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<meta name=\"generator\" content=\"Piwigo" ) || ContainsString( res, "<title>Piwigo, Welcome" ) || ( ContainsString( res, ">Piwigo<" ) && ContainsString( res, ">Login<" ) )){
		version = "unknown";
		vers = eregmatch( pattern: "js\\?v([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "piwigo/version", value: version );
		}
		set_kb_item( name: "piwigo/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:piwigo:piwigo:" );
		if(!cpe){
			cpe = "cpe:/a:piwigo:piwigo";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Piwigo", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
	}
}
exit( 0 );

