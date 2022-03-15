if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106552" );
	script_version( "2021-04-22T08:43:12+0000" );
	script_tag( name: "last_modification", value: "2021-04-22 08:43:12 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-01-30 15:26:27 +0700 (Mon, 30 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dell EMC PowerScale OneFS (Isilion OneFS) Detection (SNMP)" );
	script_tag( name: "summary", value: "SNMP based detection of Dell EMC PowerScale OneFS (formerly
  Isilion OneFS)." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(ContainsString( sysdesc, "Isilon OneFS" )){
	version = "unknown";
	set_kb_item( name: "dell/emc_isilon/onefs/detected", value: TRUE );
	set_kb_item( name: "dell/emc_isilon/onefs/snmp/port", value: port );
	set_kb_item( name: "dell/emc_isilon/onefs/snmp/" + port + "/concluded", value: sysdesc );
	vers = eregmatch( pattern: "Isilon OneFS v([0-9.]+)", string: sysdesc );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "dell/emc_isilon/onefs/snmp/" + port + "/version", value: version );
}
exit( 0 );

