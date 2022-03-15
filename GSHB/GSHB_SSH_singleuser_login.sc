if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96078" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-09 15:04:43 +0200 (Fri, 09 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Read /etc/inittab, /etc/init/rcS.conf and /etc/event.d/rcS-sulogin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to Read /etc/inittab, /etc/init/rcS.conf and /etc/event.d/rcS-sulogin." );
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
	set_kb_item( name: "GSHB/inittab", value: "error" );
	set_kb_item( name: "GSHB/rcSconf", value: "error" );
	set_kb_item( name: "GSHB/rcSsulogin", value: "error" );
	set_kb_item( name: "GSHB/inittab/log", value: error );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/inittab", value: "windows" );
	set_kb_item( name: "GSHB/rcSconf", value: "windows" );
	set_kb_item( name: "GSHB/rcSsulogin", value: "windows" );
	exit( 0 );
}
inittab = ssh_cmd( socket: sock, cmd: "LANG=C cat /etc/inittab" );
rcSconf = ssh_cmd( socket: sock, cmd: "LANG=C cat /etc/init/rcS.conf" );
rcSsulogin = ssh_cmd( socket: sock, cmd: "LANG=C cat /etc/event.d/rcS-sulogin" );
if(ContainsString( inittab, "cat: command not found" )){
	inittab = "nocat";
}
if(ContainsString( rcSconf, "cat: command not found" )){
	rcSconf = "nocat";
}
if(ContainsString( rcSsulogin, "cat: command not found" )){
	rcSsulogin = "nocat";
}
if( ContainsString( inittab, "cat: /etc/inittab: Permission denied" ) ) {
	inittab = "noperm";
}
else {
	if(IsMatchRegexp( inittab, ".*o such file or directory.*" )){
		inittab = "none";
	}
}
if( ContainsString( rcSconf, "cat: /etc/init/rcS.conf: Permission denied" ) ) {
	rcSconf = "noperm";
}
else {
	if(IsMatchRegexp( rcSconf, ".*o such file or directory.*" )){
		rcSconf = "none";
	}
}
if( ContainsString( rcSsulogin, "cat: /etc/event.d/rcS-sulogin: Permission denied" ) ) {
	initrcSsulogintab = "noperm";
}
else {
	if(IsMatchRegexp( rcSsulogin, ".*o such file or directory.*" )){
		rcSsulogin = "none";
	}
}
if( !ContainsString( inittab, "none" ) && !ContainsString( inittab, "noperm" ) ){
	inittabS = egrep( string: inittab, pattern: "(.){1,4}:S:.*:.*", icase: 1 );
	inittab1 = egrep( string: inittab, pattern: "(.){1,4}:1:.*:.*", icase: 1 );
	if(inittabS == ""){
		inittabS = "none";
	}
	if(inittab1 == ""){
		inittab1 = "none";
	}
	set_kb_item( name: "GSHB/inittab", value: 1 );
	set_kb_item( name: "GSHB/inittabS", value: inittabS );
	set_kb_item( name: "GSHB/inittab1", value: inittab1 );
}
else {
	set_kb_item( name: "GSHB/inittab", value: inittab );
	set_kb_item( name: "GSHB/inittabS", value: "none" );
	set_kb_item( name: "GSHB/inittab1", value: "none" );
}
if(!ContainsString( rcSconf, "none" ) && !ContainsString( rcSconf, "noperm" )){
	rcSconfwrong = egrep( string: rcSconf, pattern: "exec /bin/bash", icase: 0 );
	rcSconfright = egrep( string: rcSconf, pattern: "exec /sbin/sulogin", icase: 0 );
	if( rcSconfwrong != "" ) {
		rcSconf = "wrong:" + rcSconfwrong;
	}
	else {
		if( rcSconfright != "" ) {
			rcSconf = "right:" + rcSconfright;
		}
		else {
			if(( rcSconfright == "" && rcSconfwrong == "" ) || ( rcSconfright != "" && rcSconfwrong != "" )){
				rcSconf = "unknown:" + rcSconfright + rcSconfwrong;
			}
		}
	}
}
if(!ContainsString( rcSsulogin, "none" ) && !ContainsString( rcSsulogin, "noperm" )){
	rcSsuloginwrong = egrep( string: rcSsulogin, pattern: "exec /bin/bash", icase: 0 );
	rcSsuloginright = egrep( string: rcSsulogin, pattern: "exec /sbin/sulogin", icase: 0 );
	if( rcSsuloginwrong != "" ) {
		rcSsulogin = "wrong:" + rcSsuloginwrong;
	}
	else {
		if( rcSsuloginright != "" ) {
			rcSsulogin = "right:" + rcSsuloginright;
		}
		else {
			if(( rcSsuloginright == "" && rcSsuloginwrong == "" ) || ( rcSsuloginright != "" && rcSsuloginwrong != "" )){
				rcSsulogin = "unknown:" + rcSsuloginright + ":" + rcSsuloginwrong;
			}
		}
	}
}
set_kb_item( name: "GSHB/rcSconf", value: rcSconf );
set_kb_item( name: "GSHB/rcSsulogin", value: rcSsulogin );
exit( 0 );

