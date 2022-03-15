if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140810" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-02-26 13:19:50 +0700 (Mon, 26 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Siemens RUGGEDCOM Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Siemens RUGGEDCOM devices." );
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
if(!sysdesc = snmp_get_sysdescr( port: port )){
	exit( 0 );
}
if(!ContainsString( sysdesc, "Siemens, SIMATIC NET, RUGGEDCOM" ) && !ContainsString( sysdesc, "RuggedCom" )){
	exit( 0 );
}
set_kb_item( name: "siemens_ruggedcom/detected", value: TRUE );
set_kb_item( name: "siemens_ruggedcom/snmp/detected", value: TRUE );
set_kb_item( name: "siemens_ruggedcom/snmp/port", value: port );
prod = eregmatch( pattern: "RUGGEDCOM ([^\r\n,]+)", string: sysdesc, icase: TRUE );
if(!isnull( prod[1] )){
	set_kb_item( name: "siemens_ruggedcom/snmp/" + port + "/model", value: prod[1] );
}
vers = eregmatch( pattern: "FW: Version V([0-9.]+)", string: sysdesc );
if( !isnull( vers[1] ) ){
	set_kb_item( name: "siemens_ruggedcom/snmp/" + port + "/version", value: vers[1] );
	set_kb_item( name: "siemens_ruggedcom/snmp/" + port + "/concluded", value: vers[0] );
}
else {
	fw_oid = "1.3.6.1.4.1.15004.4.2.3.3.0";
	fw_res = snmp_get( port: port, oid: fw_oid );
	vers = eregmatch( pattern: "ROX ([0-9.]+)", string: fw_res );
	if(!isnull( vers[1] )){
		set_kb_item( name: "siemens_ruggedcom/snmp/" + port + "/version", value: vers[1] );
		set_kb_item( name: "siemens_ruggedcom/snmp/" + port + "/concluded", value: vers[0] );
		set_kb_item( name: "siemens_ruggedcom/snmp/" + port + "/concludedOID", value: fw_oid );
		set_kb_item( name: "siemens_ruggedcom/isROX", value: TRUE );
	}
}
exit( 0 );

