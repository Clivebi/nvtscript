if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143662" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-03-31 08:53:09 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "DrayTek Vigor Detection (SNMP)" );
	script_tag( name: "summary", value: "Detection of DrayTek Vigor devices.

  This script performs SNMP based detection of DrayTek Vigor devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(!IsMatchRegexp( sysdesc, "^DrayTek.+Router Model" ) && !IsMatchRegexp( sysdesc, "^DrayTek Corporation" ) && !IsMatchRegexp( sysdesc, "^Linux Draytek " )){
	exit( 0 );
}
set_kb_item( name: "draytek/vigor/detected", value: TRUE );
set_kb_item( name: "draytek/vigor/snmp/port", value: port );
set_kb_item( name: "draytek/vigor/snmp/" + port + "/concluded", value: sysdesc );
model = "unknown";
version = "unknown";
mod = eregmatch( pattern: "Router Model: Vigor([0-9]+)", string: sysdesc );
if(!isnull( mod[1] )){
	model = mod[1];
}
vers = eregmatch( pattern: "Version: ([^/,]+)", string: sysdesc );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "draytek/vigor/snmp/" + port + "/model", value: model );
set_kb_item( name: "draytek/vigor/snmp/" + port + "/version", value: version );
exit( 0 );

