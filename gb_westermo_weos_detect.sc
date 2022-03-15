if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106196" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-08-24 11:10:05 +0700 (Wed, 24 Aug 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Westermo WeOS Detection (SNMP)" );
	script_tag( name: "summary", value: "Detection of Westermo WeOS.

  This script performs SNMP based detection of Westermo WeOS." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_xref( name: "URL", value: "http://www.westermo.com" );
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
if(egrep( string: sysdesc, pattern: "^Westermo.*, primary:.*, backup:.*, bootloader:" )){
	model = "unknown";
	version = "unknown";
	mo = eregmatch( pattern: "Westermo (.*), primary:", string: sysdesc );
	if(!isnull( mo[1] )){
		model = mo[1];
	}
	vers = eregmatch( pattern: "primary: v([0-9.]+)", string: sysdesc );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "westermo/weos/detected", value: TRUE );
	if(model != "unknown"){
		set_kb_item( name: "westermo/weos/model", value: model );
	}
	if(version != "unknown"){
		set_kb_item( name: "westermo/weos/version", value: version );
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/o:westermo:weos:" );
	if(!cpe){
		cpe = "cpe:/o:westermo:weos";
	}
	os_register_and_report( os: "Westermo WeOS", cpe: cpe, banner_type: "SNMP sysDescr", port: port, proto: "udp", banner: sysdesc, desc: "Westermo WeOS Detection (SNMP)", runs_key: "unixoide" );
	register_product( cpe: cpe, location: port + "/udp", port: port, proto: "udp", service: "snmp" );
	log_message( data: build_detection_report( app: "Westermo WeOS on model " + model, version: version, install: port + "/udp", cpe: cpe, concluded: sysdesc ), port: port, proto: "udp" );
	exit( 0 );
}
exit( 0 );

