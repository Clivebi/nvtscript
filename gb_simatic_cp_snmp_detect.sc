if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140736" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-02-01 15:08:26 +0700 (Thu, 01 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Siemens SIMATIC CP Device Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Siemens SIMATIC CP devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	exit( 0 );
}
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(egrep( string: sysdesc, pattern: "Siemens, SIMATIC NET, CP" )){
	set_kb_item( name: "simatic_cp/detected", value: TRUE );
	set_kb_item( name: "simatic_cp/snmp/detected", value: TRUE );
	set_kb_item( name: "simatic_cp/snmp/port", value: port );
	sp = split( buffer: sysdesc, sep: ",", keep: FALSE );
	if(!isnull( sp[2] )){
		model = eregmatch( pattern: "(CP.*)", string: sp[2] );
		if(!isnull( model[1] )){
			set_kb_item( name: "simatic_cp/snmp/" + port + "/model", value: model[1] );
		}
	}
	if(!isnull( sp[5] )){
		version = eregmatch( pattern: "V([0-9.]+)", string: sp[5] );
		if(!isnull( version[1] )){
			set_kb_item( name: "simatic_cp/snmp/" + port + "/version", value: version[1] );
		}
	}
	if(!isnull( sp[3] )){
		module = eregmatch( pattern: "^ (.*)", string: sp[3] );
		set_kb_item( name: "simatic_cp/snmp/" + port + "/module", value: module[1] );
	}
	if(!isnull( sp[4] )){
		hw = eregmatch( pattern: "HW: Version ([0-9]+)", string: sp[4] );
		set_kb_item( name: "simatic_cp/snmp/" + port + "/hw_version", value: hw[1] );
	}
}
exit( 0 );

