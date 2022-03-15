if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117234" );
	script_version( "2021-04-15T12:34:28+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 12:34:28 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-02-25 15:17:04 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Sony BRAVIA TV Detection (UPnP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_upnp_detect.sc" );
	script_mandatory_keys( "upnp/identified" );
	script_tag( name: "summary", value: "UPnP based detection of Sony BRAVIA TV devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = service_get_port( default: 1900, ipproto: "udp", proto: "upnp" );
banner = get_kb_item( "upnp/" + port + "/banner" );
if(!banner || !ContainsString( banner, "USN:" )){
	exit( 0 );
}
if(concl = egrep( pattern: "^USN:.+SONY.+BRAVIA", string: banner, icase: FALSE )){
	concl = chomp( concl );
	install = port + "/udp";
	version = "unknown";
	cpe = "cpe:/h:sony:bravia";
	set_kb_item( name: "sony/bravia_tv/detected", value: TRUE );
	set_kb_item( name: "sony/bravia_tv/upnp/detected", value: TRUE );
	register_product( cpe: cpe, location: install, port: port, service: "upnp", proto: "udp" );
	log_message( port: port, proto: "udp", data: build_detection_report( app: "Sony BRAVIA TV", version: version, install: install, cpe: cpe, concluded: concl ) );
}
exit( 0 );

