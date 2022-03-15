if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108244" );
	script_version( "2020-03-26T08:48:45+0000" );
	script_tag( name: "last_modification", value: "2020-03-26 08:48:45 +0000 (Thu, 26 Mar 2020)" );
	script_tag( name: "creation_date", value: "2017-09-25 10:52:11 +0200 (Mon, 25 Sep 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Get the MAC Address over SNMP" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SNMP" );
	script_dependencies( "snmp_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/detected" );
	script_tag( name: "summary", value: "This script attempts to gather the MAC address of the target via SNMP." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
if(defined_func( "snmpv3_get" )){
	ip = get_host_ip();
	if(isnull( id = snmp_get( port: port, oid: "1.3.6.1.2.1.4.20.1.2." + ip ) )){
		exit( 0 );
	}
	if(!mac = snmp_get( port: port, oid: "1.3.6.1.2.1.2.2.1.6." + id )){
		exit( 0 );
	}
	mac = str_replace( string: mac, find: " ", replace: ":" );
	mac = eregmatch( pattern: "([0-9a-fA-F:]{17})", string: mac );
	if(!isnull( mac[1] )){
		register_host_detail( name: "MAC", value: mac[1], desc: "Get the MAC Address over SNMP" );
		replace_kb_item( name: "Host/mac_address", value: mac[1] );
	}
}
exit( 0 );

