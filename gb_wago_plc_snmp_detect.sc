if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141767" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-12-07 13:21:00 +0700 (Fri, 07 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "WAGO PLC Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of WAGO PLC Controllers." );
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
if(IsMatchRegexp( sysdesc, "^WAGO " )){
	set_kb_item( name: "wago_plc/detected", value: TRUE );
	set_kb_item( name: "wago_plc/snmp/detected", value: TRUE );
	set_kb_item( name: "wago_plc/snmp/port", value: port );
	set_kb_item( name: "wago_plc/snmp/" + port + "/concluded", value: sysdesc );
	mod = eregmatch( pattern: "WAGO (.*)", string: sysdesc );
	if(!isnull( mod[1] )){
		set_kb_item( name: "wago_plc/snmp/" + port + "/model", value: mod[1] );
	}
	exit( 0 );
}
exit( 0 );

