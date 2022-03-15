if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141389" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-08-23 12:36:07 +0700 (Thu, 23 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Silver Peak Appliance Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs an SNMP based detection of Silver Peak appliances." );
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
if(!sysdesc = snmp_get_sysdescr( port: port )){
	exit( 0 );
}
if(!IsMatchRegexp( sysdesc, "Silver Peak Systems, Inc\\. (EC|NX|VX)" ) || !ContainsString( sysdesc, "VXOA " )){
	exit( 0 );
}
set_kb_item( name: "silverpeak_appliance/detected", value: TRUE );
set_kb_item( name: "silverpeak_appliance/snmp/detected", value: TRUE );
set_kb_item( name: "silverpeak_appliance/snmp/port", value: port );
set_kb_item( name: "silverpeak_appliance/snmp/" + port + "/concluded", value: sysdesc );
mod = eregmatch( pattern: "Silver Peak Systems, Inc. ((EC(V|XS|S|M|L|XL))|NX[0-9]+k?|VX[0-9]+)", string: sysdesc );
if(!isnull( mod[1] )){
	set_kb_item( name: "silverpeak_appliance/snmp/" + port + "/model", value: mod[1] );
}
vers = eregmatch( pattern: "VXOA ([0-9._]+)", string: sysdesc );
if(!isnull( vers[1] )){
	set_kb_item( name: "silverpeak_appliance/snmp/" + port + "/version", value: vers[1] );
}
exit( 0 );

