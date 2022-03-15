if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96074" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "List Users, who was since 84 days not logged in to the System." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to List Users, who was since 84 days not logged in to the System." );
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
	set_kb_item( name: "GSHB/lastlogin", value: "error" );
	set_kb_item( name: "GSHB/LockedUser", value: "error" );
	set_kb_item( name: "GSHB/UserShell", value: "error" );
	set_kb_item( name: "GSHB/lastlogin/log", value: error );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/lastlogin", value: "windows" );
	set_kb_item( name: "GSHB/LockedUser", value: "windows" );
	set_kb_item( name: "GSHB/UserShell", value: "windows" );
	exit( 0 );
}
lastlogin = ssh_cmd( socket: sock, cmd: "lastlog -b 84" );
if(ContainsString( lastlogin, "grep: " )){
	lastlogin = "none";
}
if(!lastlogin){
	lastlogin = "none";
}
set_kb_item( name: "GSHB/lastlogin", value: lastlogin );
passwd = ssh_cmd( socket: sock, cmd: "cat /etc/passwd" );
LockLst = split( buffer: passwd, keep: 0 );
for(i = 0;i < max_index( LockLst );i++){
	LockUserLst = split( buffer: LockLst[i], sep: ":", keep: 0 );
	if(LockUserLst[1] != "x" && LockUserLst[1] != ""){
		LockUser += LockUserLst[0] + "\n";
	}
}
if(!LockUser){
	LockUser = "none";
}
set_kb_item( name: "GSHB/LockedUser", value: LockUser );
lowpasswd = tolower( passwd );
ShellLst = split( buffer: lowpasswd, keep: 0 );
for(i = 0;i < max_index( ShellLst );i++){
	ShellUserLst = split( buffer: ShellLst[i], sep: ":", keep: 0 );
	if(ShellUserLst[6] != "/bin/false" && ShellUserLst[6] != "/usr/sbin/nologin" && ShellUserLst[6] != "/bin/sh"){
		ShellUser += ShellUserLst[0] + ":" + ShellUserLst[6] + "\n";
	}
}
if(!ShellUser){
	ShellUser = "none";
}
set_kb_item( name: "GSHB/UserShell", value: ShellUser );
exit( 0 );

