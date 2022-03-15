if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108301" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-11-29 08:03:31 +0100 (Wed, 29 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Lantronix Devices Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Lantronix Devices." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("snmp_func.inc.sc");
require("misc_func.inc.sc");
port = snmp_get_port( default: 161 );
if(!sysdesc = snmp_get_sysdescr( port: port )){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^Lantronix" )){
	set_kb_item( name: "lantronix_device/detected", value: TRUE );
	set_kb_item( name: "lantronix_device/snmp/detected", value: TRUE );
	set_kb_item( name: "lantronix_device/snmp/port", value: port );
	version = "unknown";
	type = "unknown";
	vers_nd_type = eregmatch( pattern: "^Lantronix ([A-Z0-9-]+) .*(V|B|Version )([0-9.]+)", string: sysdesc, icase: FALSE );
	if(vers_nd_type[1]){
		type = vers_nd_type[1];
	}
	if(vers_nd_type[3]){
		version = vers_nd_type[3];
	}
	set_kb_item( name: "lantronix_device/snmp/" + port + "/type", value: type );
	set_kb_item( name: "lantronix_device/snmp/" + port + "/version", value: version );
	set_kb_item( name: "lantronix_device/snmp/" + port + "/concluded", value: sysdesc );
}
exit( 0 );

