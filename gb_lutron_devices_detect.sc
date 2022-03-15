if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812952" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-27 16:58:19 +0530 (Tue, 27 Feb 2018)" );
	script_name( "Lutron Devices Remote Detection" );
	script_tag( name: "summary", value: "Detection of Lutron Devices.

  The script sends a connection request to the server and attempts to detect the
  presence of Lutron Devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
lutPort = http_get_port( default: 80 );
res = http_get_cache( port: lutPort, item: "/" );
if(ContainsString( res, "<h1>LUTRON</h1>" ) && ContainsString( res, "name=\"login\"" ) && "name=\"password\""){
	version = "unknown";
	set_kb_item( name: "lutron/detected", value: TRUE );
	cpe = "cpe:/a:lutron:device";
	register_product( cpe: cpe, location: "/", port: lutPort, service: "www" );
	log_message( data: build_detection_report( app: "LutPort Device", version: version, install: "/", cpe: cpe, concluded: "LutPort Device Detected" ), port: lutPort );
	exit( 0 );
}
exit( 0 );

