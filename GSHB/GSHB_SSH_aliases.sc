if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96067" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "List /etc/aliases" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to List /etc/aliases." );
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
	set_kb_item( name: "GSHB/Aliasesrights", value: "error" );
	set_kb_item( name: "GSHB/Aliasescont", value: "error" );
	set_kb_item( name: "GSHB/Aliasescont/log", value: error );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/Aliasesrights", value: "windows" );
	set_kb_item( name: "GSHB/Aliasescont", value: "windows" );
	exit( 0 );
}
aliasesrights = ssh_cmd( socket: sock, cmd: "ls -l cat /etc/aliases" );
if(ContainsString( aliasesrights, "ls: " )){
	aliasesrights = "noaliases";
}
if( !aliasesrights ) {
	aliasesrights = "noaliases";
}
else {
	val = split( buffer: aliasesrights, sep: " ", keep: 0 );
	aliasesrights = val[0] + " " + val[2] + " " + val[3];
}
aliasescont = ssh_cmd( socket: sock, cmd: "cat /etc/aliases" );
if(ContainsString( aliasescont, "cat: /etc/aliases:" )){
	aliasescont = "noaliases";
}
if(!aliasescont){
	aliasescont = "noaliases";
}
set_kb_item( name: "GSHB/Aliasesrights", value: aliasesrights );
set_kb_item( name: "GSHB/Aliasescont", value: aliasescont );
exit( 0 );

