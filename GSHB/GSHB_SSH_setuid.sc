if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96069" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "List Files with setuid-bit in / and /home, Check /tmp for sticky-bit" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to List Files with setuid-bit in / and /home, Check /tmp for sticky-bit." );
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
	set_kb_item( name: "GSHB/tempsticky", value: "error" );
	set_kb_item( name: "GSHB/setuid/home", value: "error" );
	set_kb_item( name: "GSHB/setuid/root", value: "error" );
	set_kb_item( name: "GSHB/setuid/log", value: error );
	exit( 0 );
}
tempsticky = ssh_cmd( socket: sock, cmd: "ls -ld /tmp" );
if( ContainsString( tempsticky, "ls: " ) ) {
	tempsticky = "notmp";
}
else {
	val = split( buffer: tempsticky, sep: " ", keep: 0 );
	if( !ContainsString( val[0], "t" ) ) {
		tempsticky = "false";
	}
	else {
		tempsticky = "true";
	}
}
homesetuid = ssh_cmd( socket: sock, cmd: "find /home -perm +4000 -type f" );
rootsetuid = ssh_cmd( socket: sock, cmd: "find / -perm +4000 -type f" );
if(ContainsString( homesetuid, "FIND: Invalid switch" ) || ContainsString( homesetuid, "FIND: Parameterformat falsch" )){
	set_kb_item( name: "GSHB/tempsticky", value: "windows" );
	set_kb_item( name: "GSHB/setuid/home", value: "windows" );
	set_kb_item( name: "GSHB/setuid/root", value: "windows" );
	exit( 0 );
}
if(!homesetuid){
	homesetuid = "none";
}
if(ContainsString( homesetuid, "FIND:" ) || ContainsString( homesetuid, "find:" )){
	homesetuid = "none";
}
if(!rootsetuid){
	rootsetuid = "none";
}
if(ContainsString( rootsetuid, "FIND:" ) || ContainsString( rootsetuid, "find:" )){
	rootsetuid = "none";
}
set_kb_item( name: "GSHB/tempsticky", value: tempsticky );
set_kb_item( name: "GSHB/setuid/home", value: homesetuid );
set_kb_item( name: "GSHB/setuid/root", value: rootsetuid );
exit( 0 );

