if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108337" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-02-15 11:09:51 +0100 (Thu, 15 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Brocade Fabric OS Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "The script sends an SNMP request to the device and attempts
  to detect the presence of devices running Fabric OS and to extract its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("snmp_func.inc.sc");
require("misc_func.inc.sc");
port = snmp_get_port( default: 161 );
if(!sysdesc = snmp_get_sysdescr( port: port )){
	exit( 0 );
}
fw_oid = "1.3.6.1.4.1.1588.2.1.1.1.1.6.0";
fw_res = snmp_get( port: port, oid: fw_oid );
if(IsMatchRegexp( fw_res, "^v([0-9a-z.]+)$" )){
	version = "unknown";
	set_kb_item( name: "brocade_fabricos/detected", value: TRUE );
	set_kb_item( name: "brocade_fabricos/snmp/detected", value: TRUE );
	set_kb_item( name: "brocade_fabricos/snmp/port", value: port );
	vers = eregmatch( pattern: "^v([0-9a-z.]+)", string: fw_res );
	if(vers[1]){
		version = vers[1];
		set_kb_item( name: "brocade_fabricos/snmp/" + port + "/version", value: version );
		set_kb_item( name: "brocade_fabricos/snmp/" + port + "/concluded", value: fw_res );
		set_kb_item( name: "brocade_fabricos/snmp/" + port + "/concludedOID", value: fw_oid );
	}
}
exit( 0 );

