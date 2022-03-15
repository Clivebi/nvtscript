if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106569" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-02-06 14:03:54 +0700 (Mon, 06 Feb 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dell SonicWALL TZ Detection (SNMP)" );
	script_tag( name: "summary", value: "Detection of Dell SonicWALL TZ.

  This script performs SNMP based detection of Dell SonicWALL TZ devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(ContainsString( sysdesc, "SonicWALL TZ" )){
	version = "unknown";
	mod = eregmatch( pattern: "SonicWALL TZ ([0-9]+)", string: sysdesc );
	if(isnull( mod[1] )){
		exit( 0 );
	}
	model = mod[1];
	set_kb_item( name: "sonicwall/tz/model", value: model );
	vers = eregmatch( pattern: "SonicOS Enhanced ([^)]+)", string: sysdesc );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "sonicwall/tz/version", value: version );
	}
	set_kb_item( name: "sonicwall/tz/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9a-z.-]+)", base: "cpe:/a:dell:sonicwall_totalsecure_tz_" + model + "_firmware:" );
	if(!cpe){
		cpe = "cpe:/a:dell:sonicwall_totalsecure_tz_" + model + "_firmware";
	}
	register_product( cpe: cpe, port: port, location: port + "/udp", service: "snmp", proto: "udp" );
	log_message( data: build_detection_report( app: "Dell SonicWALL TZ " + model, version: version, install: port + "/udp", cpe: cpe, concluded: sysdesc ), port: port, proto: "udp" );
	exit( 0 );
}
exit( 0 );

