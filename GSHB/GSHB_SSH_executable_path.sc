if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96084" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "List executable and writable-executable Files, list path variable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "List executable and writable-executable Files, list path variable over an SSH Connection.

  Check for executable Files outside /usr/local/bin:/usr/bin:/bin:/usr/bin/X11:
  /usr/games:/sbin:/usr/sbin:/usr/local/sbin:, check for user write permission on
  valid executables." );
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
	set_kb_item( name: "GSHB/executable", value: "error" );
	set_kb_item( name: "GSHB/write-executable", value: "error" );
	set_kb_item( name: "GSHB/path", value: "error" );
	set_kb_item( name: "GSHB/executable/log", value: error );
	exit( 0 );
}
executable = ssh_cmd( socket: sock, cmd: "find / -mount -type f -perm -001" );
writeexecutable = ssh_cmd( socket: sock, cmd: "find / -mount -type f -perm -003" );
path = ssh_cmd( socket: sock, cmd: "export" );
if( !executable ) {
	executable = "none";
}
else {
	Lst = split( buffer: executable, keep: 0 );
	executable = "";
	for(i = 0;i < max_index( Lst );i++){
		if(IsMatchRegexp( Lst[i], "^/usr/local/bin/.*" ) || IsMatchRegexp( Lst[i], "^/usr/bin/.*" ) || IsMatchRegexp( Lst[i], "^/bin/.*" ) || IsMatchRegexp( Lst[i], "^/usr/games/.*" ) || IsMatchRegexp( Lst[i], "^/sbin/.*" ) || IsMatchRegexp( Lst[i], "^/usr/sbin/.*" ) || IsMatchRegexp( Lst[i], "^/usr/local/sbin/.*" ) || IsMatchRegexp( Lst[i], "^/var/lib/.*" ) || IsMatchRegexp( Lst[i], "^/lib/.*" ) || IsMatchRegexp( Lst[i], "^/usr/lib/.*" ) || IsMatchRegexp( Lst[i], "^/etc/.*" ) || IsMatchRegexp( Lst[i], ".*Keine Berechtigung.*" ) || IsMatchRegexp( Lst[i], ".*Permission denied.*" )){
			continue;
		}
		executable += Lst[i] + "\n";
	}
}
if( !writeexecutable ) {
	writeexecutable = "none";
}
else {
	Lst = split( buffer: writeexecutable, keep: 0 );
	if(Lst){
		writeexecutable = "";
		for(i = 0;i < max_index( Lst );i++){
			if(IsMatchRegexp( Lst[i], ".*Keine Berechtigung.*" ) || IsMatchRegexp( Lst[i], ".*Permission denied.*" )){
				continue;
			}
			writeexecutable += Lst[i] + "\n";
		}
	}
}
if(writeexecutable == ""){
	writeexecutable = "none";
}
if( !path ) {
	path = "none";
}
else {
	path = egrep( string: path, pattern: " PATH=", icase: 0 );
}
set_kb_item( name: "GSHB/executable", value: executable );
set_kb_item( name: "GSHB/write-executable", value: writeexecutable );
set_kb_item( name: "GSHB/path", value: path );
exit( 0 );

