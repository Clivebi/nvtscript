if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140257" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-07-31 13:26:04 +0700 (Mon, 31 Jul 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Thycotic Secret Server Detection" );
	script_tag( name: "summary", value: "Detection of Thycotic Secret Server.

The script sends a connection request to the server and attempts to detect Thycotic Secret Server and to extract
its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://thycotic.com/products/secret-server/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/SecretServer", "/secretserver", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/Login.aspx" );
	if(ContainsString( res, "Thycotic Secret Server" ) && ContainsString( res, "headerControl_EditionNameLabel" )){
		version = "unknown";
		vers = eregmatch( pattern: "VersionLabel\">Version: ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "thycotic_secretserver/version", value: version );
		}
		set_kb_item( name: "thycotic_secretserver/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:thycotic:secret_server:" );
		if(!cpe){
			cpe = "cpe:/a:thycotic:secret_server";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Thycotic Secret Server", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

