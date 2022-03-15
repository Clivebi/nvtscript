if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800353" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)" );
	script_name( "OpenFire Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9090 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed
  version of OpenFire." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9090 );
res = http_get_cache( item: "/login.jsp", port: port );
if(isnull( res )){
	exit( 0 );
}
if(ContainsString( res, "Openfire Admin Console" )){
	version = "unknown";
	install = "/";
	ver = eregmatch( pattern: "Openfire, Version: ([0-9.]+)", string: res );
	if(ver[1]){
		version = ver[1];
	}
	set_kb_item( name: "www/" + port + "/Openfire", value: version );
	set_kb_item( name: "OpenFire/Installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:igniterealtime:openfire:" );
	if(!cpe){
		cpe = "cpe:/a:igniterealtime:openfire";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "OpenFire", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
}
exit( 0 );

