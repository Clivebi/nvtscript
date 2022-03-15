if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900811" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Asterisk Detection (SIP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	script_tag( name: "summary", value: "Detection of Asterisk.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(banner && ( ContainsString( banner, "Asterisk PBX" ) || ContainsString( banner, "FPBX-" ) )){
	version = "unknown";
	asteriskVer = eregmatch( pattern: "Asterisk PBX (certified/)?([0-9.]+(.?[a-z0-9]+)?)", string: banner );
	if( !isnull( asteriskVer[2] ) ){
		version = ereg_replace( pattern: "-", replace: ".", string: asteriskVer[2] );
		set_kb_item( name: "Asterisk-PBX/Ver", value: version );
	}
	else {
		vers = eregmatch( pattern: "FPBX-[0-9.]+\\(([0-9.]+[^)]+)\\)", string: banner );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "Asterisk-PBX/Ver", value: version );
		}
	}
	set_kb_item( name: "Asterisk-PBX/Installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+\\.[0-9]+)\\.?((rc[0-9]+)|(cert[1-9]))?", base: "cpe:/a:digium:asterisk:" );
	if(!cpe){
		cpe = "cpe:/a:digium:asterisk";
	}
	location = port + "/" + proto;
	register_product( cpe: cpe, port: port, location: location, service: "sip", proto: proto );
	log_message( data: build_detection_report( app: "Asterisk-PBX", version: version, install: location, cpe: cpe, concluded: banner ), port: port, proto: proto );
}
exit( 0 );

