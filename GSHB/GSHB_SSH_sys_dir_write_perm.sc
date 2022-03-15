if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96081" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "Check write permissions of system-directorys" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to Check write permissions of system-directorys." );
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
	set_kb_item( name: "GSHB/Dir-Writeperm", value: "error" );
	set_kb_item( name: "GSHB/Dir-Writeperm/log", value: error );
	exit( 0 );
}
writeperm = ssh_cmd( socket: sock, cmd: "find / -mount -type d -perm -002" );
if( !writeperm ) {
	writeperm = "none";
}
else {
	if(writeperm != "none"){
		Lst = split( buffer: writeperm, keep: 0 );
		if( Lst ){
			for(i = 0;i < max_index( Lst );i++){
				if(ContainsString( Lst[i], "/home/" ) || ContainsString( Lst[i], "/tmp" ) || ContainsString( Lst[i], "Keine Berechtigung" ) || ContainsString( Lst[i], "Permission denied" )){
					continue;
				}
				ClearLst += Lst[i] + "\n";
			}
		}
		else {
			if(!ContainsString( Lst[i], "/home/" ) && !ContainsString( Lst[i], "/tmp" ) && !ContainsString( Lst[i], "Keine Berechtigung" ) && !ContainsString( Lst[i], "Permission denied" )){
				Clearlist = writeperm;
			}
		}
	}
}
if( ContainsString( ClearLst, "FIND: Invalid switch" ) || ContainsString( ClearLst, "FIND: Parameterformat falsch" ) ) {
	ClearLst = "windows";
}
else {
	if( IsMatchRegexp( ClearLst, "(F|f)(I|i)(N|n)(D|d): .*" ) ) {
		ClearLst = "nofind";
	}
	else {
		if(!ClearLst){
			ClearLst = "none";
		}
	}
}
set_kb_item( name: "GSHB/Dir-Writeperm", value: ClearLst );
exit( 0 );

