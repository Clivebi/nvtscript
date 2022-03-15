if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800559" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Adobe Flash Media Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8086 );
	script_mandatory_keys( "FlashCom/banner" );
	script_tag( name: "summary", value: "This script detects the version of Adobe Flash Media Server and
  sets the result in the KB." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8086 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "erver: FlashCom" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "FlashCom/([0-9.]+)", string: banner );
if(!isnull( vers )){
	version = vers[1];
}
set_kb_item( name: "www/" + port + "/Adobe/FMS", value: version );
set_kb_item( name: "Adobe/FMS/installed", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:adobe:flash_media_server:" );
if(!cpe){
	cpe = "cpe:/a:adobe:flash_media_server";
}
register_product( cpe: cpe, location: port + "/tcp", port: port, service: "www" );
log_message( data: build_detection_report( app: "Adobe Flash Media Server", version: version, install: port + "/tcp", cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );

