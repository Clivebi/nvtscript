if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108163" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-05-18 10:24:16 +0200 (Thu, 18 May 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NETGEAR ProSAFE Devices Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of NETGEAR ProSAFE devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc || ( !ContainsString( sysdesc, "ProSafe" ) && !ContainsString( sysdesc, "ProSAFE" ) )){
	exit( 0 );
}
set_kb_item( name: "netgear/prosafe/detected", value: TRUE );
set_kb_item( name: "netgear/prosafe/snmp/detected", value: TRUE );
set_kb_item( name: "netgear/prosafe/snmp/port", value: port );
model = "unknown";
fw_version = "unknown";
fw_build = "unknown";
if( ContainsString( sysdesc, "Netgear ProSafe VPN Firewall" ) ){
	pattern = "^Netgear ProSafe VPN Firewall ([0-9a-zA-Z\\-]+)";
}
else {
	if( ContainsString( sysdesc, "ProSafe 802.11b/g Wireless Access Point" ) ){
		pattern = "^ProSafe 802.11b/g Wireless Access Point -([0-9a-zA-Z\\-]+) V([0-9.]+)";
	}
	else {
		pattern = "^([0-9a-zA-Z\\-]+) [- ]+?ProSafe[^,]+(, ([0-9.]+), B?([0-9.]+))?";
		offset = 1;
	}
}
model_fw_nd_build = eregmatch( pattern: pattern, string: sysdesc, icase: TRUE );
if(!isnull( model_fw_nd_build[1] )){
	model = model_fw_nd_build[1];
}
if(!isnull( model_fw_nd_build[2] )){
	fw_version = model_fw_nd_build[2 + offset];
}
if(!isnull( model_fw_nd_build[3] )){
	fw_build = model_fw_nd_build[3 + offset];
}
set_kb_item( name: "netgear/prosafe/snmp/" + port + "/model", value: model );
set_kb_item( name: "netgear/prosafe/snmp/" + port + "/fw_version", value: fw_version );
set_kb_item( name: "netgear/prosafe/snmp/" + port + "/fw_build", value: fw_build );
set_kb_item( name: "netgear/prosafe/snmp/" + port + "/concluded", value: sysdesc );
exit( 0 );

