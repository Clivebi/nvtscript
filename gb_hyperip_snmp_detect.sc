if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108349" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NetEx HyperIP Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of a NetEx HyperIP
  virtual appliance." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc || !IsMatchRegexp( sysdesc, "^HyperIP" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "^HyperIP ([0-9.]+)", string: sysdesc );
if(vers[1]){
	version = vers[1];
}
set_kb_item( name: "hyperip/detected", value: TRUE );
set_kb_item( name: "hyperip/snmp/detected", value: TRUE );
set_kb_item( name: "hyperip/snmp/port", value: port );
set_kb_item( name: "hyperip/snmp/" + port + "/concluded", value: sysdesc );
set_kb_item( name: "hyperip/snmp/" + port + "/version", value: version );
exit( 0 );

