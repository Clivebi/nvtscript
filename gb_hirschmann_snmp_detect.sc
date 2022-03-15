if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108313" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-12-11 11:03:31 +0100 (Mon, 11 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Hirschmann Devices Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Hirschmann Devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc || !IsMatchRegexp( sysdesc, "^Hirschmann" )){
	exit( 0 );
}
set_kb_item( name: "hirschmann_device/detected", value: TRUE );
set_kb_item( name: "hirschmann_device/snmp/detected", value: TRUE );
set_kb_item( name: "hirschmann_device/snmp/port", value: port );
fw_version = "unknown";
product_name = "unknown";
platform_name = "unknown";
prod_name = eregmatch( pattern: "^Hirschmann ([^\n0-9]+)", string: sysdesc );
if(prod_name[1]){
	product_name = chomp( prod_name[1] );
}
oid = snmp_get( port: port, oid: "1.3.6.1.4.1.248.14.1.1.2.0" );
sw_banner = eregmatch( pattern: "^SW: (.*) CH: ", string: oid );
if( sw_banner ){
	set_kb_item( name: "hirschmann_device/snmp/" + port + "/concluded", value: oid );
	set_kb_item( name: "hirschmann_device/snmp/" + port + "/concludedOID", value: "1.3.6.1.4.1.248.14.1.1.2.0" );
	vers_nd_model = eregmatch( pattern: "([0-9a-zA-Z]+)-([0-9a-zA-Z]+-)?([0-9.]+)", string: sw_banner[1] );
	if( vers_nd_model ){
		fw_version = vers_nd_model[3];
		if( vers_nd_model[2] ){
			platform_name = vers_nd_model[1] + "-";
			platform_name += ereg_replace( pattern: "-$", string: vers_nd_model[2], replace: "" );
		}
		else {
			platform_name = vers_nd_model[1];
		}
	}
	else {
		vers = eregmatch( pattern: "([0-9.]+)", string: sw_banner[1] );
		if(vers){
			fw_version = vers[1];
		}
	}
}
else {
	set_kb_item( name: "hirschmann_device/snmp/" + port + "/concluded", value: sysdesc );
}
set_kb_item( name: "hirschmann_device/snmp/" + port + "/fw_version", value: fw_version );
set_kb_item( name: "hirschmann_device/snmp/" + port + "/product_name", value: product_name );
set_kb_item( name: "hirschmann_device/snmp/" + port + "/platform_name", value: platform_name );
exit( 0 );

