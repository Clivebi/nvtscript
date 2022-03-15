if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140142" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)" );
	script_name( "EMC Data Domain Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of EMC Data Domain." );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!ContainsString( sysdesc, "Data Domain OS" )){
	exit( 0 );
}
set_kb_item( name: "emc/data_domain/installed", value: TRUE );
vb = eregmatch( pattern: "Data Domain OS ([0-9.]+[^-]+)-([0-9]+)", string: sysdesc );
if(!isnull( vb[1] )){
	set_kb_item( name: "emc/data_domain/version/snmp", value: vb[1] );
}
if(!isnull( vb[2] )){
	set_kb_item( name: "emc/data_domain/build/snmp", value: vb[2] );
}
exit( 0 );

