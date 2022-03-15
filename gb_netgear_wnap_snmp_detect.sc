if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141738" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-11-29 15:40:51 +0700 (Thu, 29 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NETGEAR WNAP/WNDAP Device Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of NETGEAR WNAP/WNDAP devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc || ( !ContainsString( sysdesc, "Linux" ) || !IsMatchRegexp( sysdesc, "WND?AP[0-9]{3}" ) )){
	exit( 0 );
}
set_kb_item( name: "netgear_wnap/detected", value: TRUE );
set_kb_item( name: "netgear_wnap/snmp/detected", value: TRUE );
set_kb_item( name: "netgear_wnap/snmp/port", value: port );
model = "unknown";
fw_version = "unknown";
mod_vers = eregmatch( pattern: "(WND?AP[0-9]+)_V([0-9.]+)", string: sysdesc );
if(!isnull( mod_vers[1] )){
	model = mod_vers[1];
}
if(!isnull( mod_vers[2] )){
	fw_version = mod_vers[2];
}
set_kb_item( name: "netgear_wnap/snmp/" + port + "/model", value: model );
set_kb_item( name: "netgear_wnap/snmp/" + port + "/fw_version", value: fw_version );
set_kb_item( name: "netgear_wnap/snmp/" + port + "/concluded", value: sysdesc );
exit( 0 );

