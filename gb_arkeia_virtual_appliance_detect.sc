if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803759" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 13:34:54 +0530 (Wed, 18 Sep 2013)" );
	script_name( "Arkeia Appliance Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the Arkeia Appliance and attempts
  to extract the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
http_port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: http_port );
if(!ContainsString( buf, "Arkeia Appliance<" ) && !ContainsString( buf, ">Arkeia Software<" )){
	exit( 0 );
}
version = eregmatch( string: buf, pattern: "v([0-9.]+)<" );
if(version[1]){
	set_kb_item( name: NASLString( "www/", http_port, "/ArkeiaAppliance" ), value: version[1] );
}
set_kb_item( name: "ArkeiaAppliance/installed", value: TRUE );
cpe = build_cpe( value: version[1], exp: "^([0-9.]+)", base: "cpe:/a:knox_software:arkeia_appliance:" );
if(isnull( cpe )){
	cpe = "cpe:/a:knox_software:arkeia_appliance";
}
register_product( cpe: cpe, location: "/", port: http_port, service: "www" );
log_message( data: build_detection_report( app: "Arkeia Appliance", version: version[1], install: "/", cpe: cpe, concluded: version[1] ), port: http_port );
exit( 0 );

