if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112449" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-12-06 11:16:11 +0100 (Thu, 06 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cradlepoint Routers Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Cradlepoint routers." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc || ( !ContainsString( sysdesc, "Cradlepoint" ) )){
	exit( 0 );
}
set_kb_item( name: "cradlepoint/router/detected", value: TRUE );
set_kb_item( name: "cradlepoint/router/snmp/detected", value: TRUE );
set_kb_item( name: "cradlepoint/router/snmp/port", value: port );
model = "unknown";
fw_version = "unknown";
model_nd_fw = eregmatch( pattern: "Cradlepoint ([A-Z0-9]+), Firmware Version ([0-9.]+)", string: sysdesc, icase: TRUE );
if(!isnull( model_nd_fw[1] )){
	model = model_nd_fw[1];
}
if(!isnull( model_nd_fw[2] )){
	fw_version = model_nd_fw[2];
}
fw_version = ereg_replace( pattern: "\\.$", string: fw_version, replace: "" );
set_kb_item( name: "cradlepoint/router/snmp/" + port + "/model", value: model );
set_kb_item( name: "cradlepoint/router/snmp/" + port + "/fw_version", value: fw_version );
set_kb_item( name: "cradlepoint/router/snmp/" + port + "/concluded", value: sysdesc );
exit( 0 );

