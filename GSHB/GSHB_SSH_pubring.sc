if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96070" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Search and get size of pubring.gpg" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to Search and get size of pubring.gpg." );
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
	set_kb_item( name: "GSHB/pubrings", value: "error" );
	set_kb_item( name: "GSHB/pubrings/log", value: error );
	exit( 0 );
}
pubringLst = ssh_cmd( socket: sock, cmd: "locate pubring.gpg" );
if(ContainsString( pubringLst, "command not found" )){
	pubringLst = ssh_cmd( socket: sock, cmd: "find /home /root -name pubring.gpg -type f -print" );
}
if(ContainsString( pubringLst, "FIND: Invalid switch" ) || ContainsString( pubringLst, "FIND: Parameterformat falsch" )){
	set_kb_item( name: "GSHB/pubrings", value: "windows" );
	exit( 0 );
}
if( pubringLst ){
	spList = split( buffer: pubringLst, keep: 0 );
	for(i = 0;i < max_index( spList );i++){
		usrpubring = ssh_cmd( socket: sock, cmd: "ls -l " + spList[i] );
		usrpubring = split( buffer: usrpubring, keep: 0 );
		usrpubringzize = split( buffer: usrpubring[0], sep: " ", keep: 0 );
		usrname = split( buffer: usrpubringzize[7], sep: "/", keep: 0 );
		a = max_index( usrname ) - 3;
		usrname = usrname[a];
		if(usrname == ""){
			usrname = usrpubringzize[7];
		}
		usrpubringzize = usrpubringzize[4];
		if(!usrname){
			usrname = usrpubringzize[7];
		}
		if(usrpubringzize > 0){
			pubrings += usrname + "\n";
		}
	}
}
else {
	pubrings = "none";
}
if(!pubrings){
	pubrings = "none";
}
set_kb_item( name: "GSHB/pubrings", value: pubrings );
exit( 0 );

