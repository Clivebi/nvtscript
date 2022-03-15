if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107252" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-11-09 14:03:54 +0700 (Thu, 09 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "D-Link DGS-1500 Detection (SNMP)" );
	script_tag( name: "summary", value: "Detection of D-Link DGS-1500.

  This script performs SNMP based detection of D-Link DGS-1500 devices." );
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
require("os_func.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(ContainsString( sysdesc, "DGS-1500" )){
	firmware = "unknown";
	ver = eregmatch( pattern: "(DGS-1500-[0-9]+)          ([0-9A-Z]+.*)", string: sysdesc );
	if(isnull( ver[1] )){
		exit( 0 );
	}
	model = ver[1];
	if(!isnull( ver[2] )){
		firmware = ver[2];
	}
	set_kb_item( name: "dgs/1500/model", value: model );
	set_kb_item( name: "dgs/1500/firmware", value: firmware );
	set_kb_item( name: "dgs/1500/detected", value: TRUE );
	cpe = build_cpe( value: firmware, exp: "^([0-9a-z.-]+)", base: "cpe:/o:d-link:" + tolower( model ) + "_firmware:" );
	if(!cpe){
		cpe = "cpe:/o:d-link:" + tolower( model ) + "_firmware";
	}
	hw_cpe = "cpe:/h:d-link:dgs-1500";
	os_register_and_report( os: "D-Link DSG-1500 Firmware", cpe: cpe, desc: "D-Link DGS-1500 Detection (SNMP)", runs_key: "unixoide" );
	register_product( cpe: cpe, port: port, location: port + "/udp", service: "snmp", proto: "udp" );
	register_product( cpe: hw_cpe, port: port, location: port + "/udp", service: "snmp", proto: "udp" );
	report = build_detection_report( app: "D-Link  " + model + " Firmware", version: firmware, install: port + "/udp", cpe: cpe, concluded: sysdesc );
	report += "\n\n";
	report += build_detection_report( app: "D-Link " + model, install: port + "/udp", cpe: hw_cpe, skip_version: TRUE );
	log_message( data: report, port: port, proto: "udp" );
	exit( 0 );
}
exit( 0 );

