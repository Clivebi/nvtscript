if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105244" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-04-07 13:29:41 +0200 (Tue, 07 Apr 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ArubaOS Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of ArubaOS." );
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
if(!ContainsString( sysdesc, "ArubaOS" )){
	exit( 0 );
}
set_kb_item( name: "ArubaOS/installed", value: TRUE );
cpe = "cpe:/o:arubanetworks:arubaos";
vers = "unknown";
build = FALSE;
model = FALSE;
install = port + "/udp";
version = eregmatch( pattern: "Version ([^ ]+)", string: sysdesc );
if(!isnull( version[1] )){
	vers = chomp( version[1] );
	set_kb_item( name: "ArubaOS/version", value: vers );
	rep_vers = vers;
	cpe += ":" + vers;
}
b = eregmatch( pattern: "Version [^ ]+ \\(([0-9]+)\\)", string: sysdesc );
if(!isnull( b[1] )){
	build = b[1];
	set_kb_item( name: "ArubaOS/build", value: build );
	rep_vers += " (" + build + ")";
	extra += "Build: " + build;
}
mod = eregmatch( pattern: "\\(MODEL: ([^)]+)\\)", string: sysdesc );
if(!isnull( mod[1] )){
	model = mod[1];
	set_kb_item( name: "ArubaOS/model", value: model );
	if(extra){
		extra += "\n";
	}
	extra += "Model: " + model;
}
register_product( cpe: cpe, port: port, proto: "udp", location: install, service: "snmp" );
os_register_and_report( os: "ArubaOS", cpe: cpe, banner_type: "SNMP sysdesc", banner: sysdesc, port: port, proto: "udp", desc: "ArubaOS Detection", runs_key: "unixoide" );
log_message( data: build_detection_report( app: "ArubaOS", version: rep_vers, install: install, cpe: cpe, extra: extra, concluded: sysdesc ), port: port, proto: "udp" );
exit( 0 );

