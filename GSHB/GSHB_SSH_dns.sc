if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96103" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-07 13:23:53 +0200 (Mon, 07 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "Check if DNS client is active and working" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to Check if DNS client is active and working." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = get_preference( "auth_port_ssh" );
if(!port){
	port = ssh_get_port( default: 22, ignore_unscanned: TRUE );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	error = ssh_get_error();
	if(!error){
		error = "No SSH Port or Connection!";
	}
	log_message( port: port, data: error );
	set_kb_item( name: "GSHB/DNSTEST/VAL1", value: "error" );
	set_kb_item( name: "GSHB/DNSTEST/VAL2", value: "error" );
	set_kb_item( name: "GSHB/DNSTEST/VAL3", value: "error" );
	set_kb_item( name: "GSHB/DNSTEST/VAL4", value: "error" );
	set_kb_item( name: "GSHB/DNSTEST/VAL5", value: "error" );
	set_kb_item( name: "GSHB/DNSTEST/log", value: error );
	exit( 0 );
}
VAL1 = ssh_cmd( socket: sock, cmd: "host www.greenbone.net" );
VAL2 = ssh_cmd( socket: sock, cmd: "host www.bsi.de" );
VAL3 = ssh_cmd( socket: sock, cmd: "host www.intevation.de" );
VAL4 = ssh_cmd( socket: sock, cmd: "host www.heise.de" );
VAL5 = ssh_cmd( socket: sock, cmd: "host www.debian.org" );
if( IsMatchRegexp( VAL1, "www.greenbone.net has address.*" ) ) {
	VAL1 = "TRUE";
}
else {
	VAL1 = "FALSE";
}
if( IsMatchRegexp( VAL2, "www.bsi.de has address.*" ) ) {
	VAL2 = "TRUE";
}
else {
	VAL2 = "FALSE";
}
if( IsMatchRegexp( VAL3, "www.intevation.de has address.*" ) ) {
	VAL3 = "TRUE";
}
else {
	VAL3 = "FALSE";
}
if( IsMatchRegexp( VAL4, "www.heise.de has address.*" ) ) {
	VAL4 = "TRUE";
}
else {
	VAL4 = "FALSE";
}
if( IsMatchRegexp( VAL5, "www.debian.org has address.*" ) ) {
	VAL5 = "TRUE";
}
else {
	VAL5 = "FALSE";
}
set_kb_item( name: "GSHB/DNSTEST/VAL1", value: VAL1 );
set_kb_item( name: "GSHB/DNSTEST/VAL2", value: VAL2 );
set_kb_item( name: "GSHB/DNSTEST/VAL3", value: VAL3 );
set_kb_item( name: "GSHB/DNSTEST/VAL4", value: VAL4 );
set_kb_item( name: "GSHB/DNSTEST/VAL5", value: VAL5 );
exit( 0 );

