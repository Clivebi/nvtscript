if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112117" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-11-10 13:04:05 +0100 (Fri, 10 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "pfSense Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of pfSense." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("snmp_func.inc.sc");
require("misc_func.inc.sc");
port = snmp_get_port( default: 161 );
if(!sysdesc = snmp_get_sysdescr( port: port )){
	exit( 0 );
}
if(ContainsString( sysdesc, "pfSense" )){
	set_kb_item( name: "pfsense/installed", value: TRUE );
	set_kb_item( name: "pfsense/snmp/installed", value: TRUE );
	set_kb_item( name: "pfsense/snmp/port", value: port );
	version = "unknown";
	vers = eregmatch( pattern: "^pfSense .* ([0-9.]+)-RELEASE .* FreeBSD", string: sysdesc );
	if(vers[1]){
		version = vers[1];
	}
	set_kb_item( name: "pfsense/snmp/" + port + "/version", value: version );
	set_kb_item( name: "pfsense/snmp/" + port + "/concluded", value: sysdesc );
}
exit( 0 );

