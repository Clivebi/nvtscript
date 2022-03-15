if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96068" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "List an Verify umask entries in /etc/profile and ~/.profile" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to List an Verify umask entries in /etc/profile and ~/.profile." );
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
	set_kb_item( name: "GSHB/umask", value: "error" );
	set_kb_item( name: "GSHB/umask/log", value: error );
	exit( 0 );
}
etcprofile = ssh_cmd( socket: sock, cmd: "cat /etc/profile" );
if(!etcprofile){
	set_kb_item( name: "GSHB/umask", value: "error" );
	set_kb_item( name: "GSHB/umask/log", value: "/etc/profile was not found" );
	exit( 0 );
}
etcprofileumask = egrep( string: etcprofile, pattern: "umask [0-7]{3,4}" );
if( !IsMatchRegexp( etcprofileumask, "(u|U)(M|m)(A|a)(S|s)(K|k) 0027" ) && !IsMatchRegexp( etcprofileumask, "(u|U)(M|m)(A|a)(S|s)(K|k) 0077" ) ) {
	etcbit = "fail";
}
else {
	etcbit = "pass";
}
UsProfLst = ssh_cmd( socket: sock, cmd: "locate /home/*/.profile" );
if(ContainsString( UsProfLst, "command not found" )){
	UsProfLst = ssh_cmd( socket: sock, cmd: "find /home -name .profile -type f -print" );
}
if(ContainsString( UsProfLst, "FIND: Invalid switch" ) || ContainsString( UsProfLst, "FIND: Parameterformat falsch" )){
	set_kb_item( name: "GSHB/umask", value: "windows" );
	exit( 0 );
}
if( UsProfLst ){
	spList = split( buffer: UsProfLst, keep: 0 );
	for(i = 0;i < max_index( spList );i++){
		usrname = split( buffer: spList[i], sep: "/", keep: 0 );
		a = max_index( usrname ) - 2;
		usrname = usrname[a];
		usrprofile = ssh_cmd( socket: sock, cmd: "cat " + spList[i] );
		usrprofileumask = egrep( string: usrprofile, pattern: "umask [0-7]{3,4}" );
		if( !ContainsString( usrprofileumask, "#" ) ){
			if(!IsMatchRegexp( usrprofileumask, "(u|U)(M|m)(A|a)(S|s)(K|k) 0027" ) && !IsMatchRegexp( usrprofileumask, "(u|U)(M|m)(A|a)(S|s)(K|k) 0077" )){
				failuser += "User: " + usrname + ", File: " + spList[i] + "=" + usrprofileumask;
			}
		}
		else {
			usrbit = "noconf";
		}
	}
}
else {
	usrbit = "noconf";
}
if(etcbit == "fail" && usrbit == "noconf"){
	umaskfail = "1";
}
if(etcbit == "pass" && failuser){
	umaskfail = "1";
}
if( umaskfail == "1" ){
	if( etcbit == "pass" && failuser ) {
		result = failuser;
	}
	else {
		if( etcbit == "fail" && usrbit == "noconf" && failuser ) {
			result = "/etc/profile = " + etcprofileumask + failuser;
		}
		else {
			result = "/etc/profile=" + etcprofileumask;
		}
	}
}
else {
	result = "none";
}
set_kb_item( name: "GSHB/umask", value: result );
exit( 0 );

