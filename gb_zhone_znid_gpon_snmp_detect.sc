if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108089" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2015-10-15 11:45:06 +0200 (Thu, 15 Oct 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ZHONE ZNID GPON Device Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "SNMP based detection of ZHONE ZNID GPON devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(!ContainsString( sysdesc, "ZNID-GPON" ) || !ContainsString( sysdesc, "Zhone Indoor Network Interface" )){
	exit( 0 );
}
model = "unknown";
version = "unknown";
set_kb_item( name: "dasanzhone/znid/detected", value: TRUE );
set_kb_item( name: "dasanzhone/znid/snmp/port", value: port );
set_kb_item( name: "dasanzhone/znid/snmp/" + port + "/concluded", value: sysdesc );
mod = eregmatch( pattern: "^ZNID-GPON-([^- ]+)", string: sysdesc );
if(!isnull( mod[1] )){
	model = mod[1];
}
vers = eregmatch( pattern: "Release S([0-9.]+)", string: sysdesc );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "dasanzhone/znid/snmp/" + port + "/model", value: model );
set_kb_item( name: "dasanzhone/znid/snmp/" + port + "/version", value: version );
exit( 0 );

