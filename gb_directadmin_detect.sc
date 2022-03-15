if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106500" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-01-09 10:12:05 +0700 (Mon, 09 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "DirectAdmin Detection" );
	script_tag( name: "summary", value: "Detection of DirectAdmin

The script sends a HTTP connection request to the server and attempts to detect the presence of DirectAdmin and
to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2222 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.directadmin.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 2222 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>DirectAdmin Login</title>" ) && ContainsString( res, "Server: DirectAdmin Daemon" )){
	version = "unknown";
	vers = eregmatch( pattern: "DirectAdmin Daemon v([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "directadmin/version", value: version );
	}
	set_kb_item( name: "directadmin/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:directadmin:directadmin:" );
	if(!cpe){
		cpe = "cpe:/a:directadmin:directadmin";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "DirectAdmin", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

