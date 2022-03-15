if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811655" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-09-08 12:12:54 +0530 (Fri, 08 Sep 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Technicolor TC7200 Modem/Router Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "Detection of Technicolor Modem/Router.

  This script performs SNMP based detection of Technicolor Modem/Router." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(ContainsString( sysdesc, "VENDOR: Technicolor" ) && ContainsString( sysdesc, "TC7200" )){
	model = "unknown";
	version = "unknown";
	mod = eregmatch( pattern: "MODEL: ([0-9A-Z]+).", string: sysdesc );
	if(!isnull( mod[1] )){
		model = mod[1];
		set_kb_item( name: "technicolor/model/version", value: model );
	}
	firmvers = eregmatch( pattern: "SW_REV: ([0-9A-Z.]+);", string: sysdesc );
	if(!isnull( firmvers[1] )){
		version = firmvers[1];
		set_kb_item( name: "technicolor/firmware/version", value: version );
	}
	set_kb_item( name: "technicolor/detected", value: TRUE );
	oscpe = build_cpe( value: firmvers[1], exp: "^([0-9.]+)", base: "cpe:/o:technicolor:tc7200_firmware:" );
	if(!oscpe){
		oscpe = "cpe:/o:technicolor:tc7200_firmware";
	}
	hwcpe = "cpe:/h:technicolor:tc7200_firmware:" + tolower( version );
	register_product( cpe: hwcpe, port: port, location: port + "/udp", service: "snmp", proto: "udp" );
	register_product( cpe: oscpe, port: port, location: port + "/udp", service: "snmp", proto: "udp" );
	os_register_and_report( cpe: oscpe, banner_type: "SNMP sysDescr OID", port: port, proto: "udp", banner: sysdesc, desc: "Technicolor TC7200 Modem/Router Detection (SNMP)", runs_key: "unixoide" );
	log_message( data: build_detection_report( app: "Technicolor TC7200", version: version, install: port + "/udp", cpe: oscpe, concluded: sysdesc ), port: port, proto: "udp" );
	exit( 0 );
}
exit( 0 );

