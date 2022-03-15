if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140058" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-11-14 17:35:01 +0100 (Mon, 14 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Brocade NetIron OS Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Brocade NetIron OS." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(!ContainsString( sysdesc, "Brocade NetIron" ) || !ContainsString( sysdesc, "IronWare" )){
	exit( 0 );
}
set_kb_item( name: "brocade_netiron/installed", value: TRUE );
cpe = "cpe:/o:brocade:netiron_os";
vers = "unknown";
version = eregmatch( pattern: "IronWare Version V([0-9.]+[^T]+)T([0-9]+)", string: sysdesc );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "brocade_netiron/os/version", value: vers );
}
if(!isnull( version[2] )){
	set_kb_item( name: "brocade_netiron/os/build", value: version[2] );
}
register_product( cpe: cpe, location: port + "/udp", port: port, proto: "udp", service: "snmp" );
os_register_and_report( os: "Brocade NetIron OS " + vers, cpe: cpe, banner_type: "SNMP sysdesc", banner: sysdesc, port: port, proto: "udp", desc: "Brocade NetIron OS Detection (SNMP)", runs_key: "unixoide" );
m = eregmatch( pattern: "^Brocade NetIron ([^ ,]+)", string: sysdesc );
if(!isnull( m[1] )){
	set_kb_item( name: "brocade_netiron/typ", value: m[1] );
}
report = build_detection_report( app: "Brocade NetIron OS", version: vers, install: port + "/udp", cpe: cpe, concluded: sysdesc );
log_message( port: port, data: report, proto: "udp" );
exit( 0 );

