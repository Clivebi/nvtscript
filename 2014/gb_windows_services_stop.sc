if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804787" );
	script_version( "$Revision: 11191 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-03 13:57:37 +0200 (Mon, 03 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2014-11-05 11:50:33 +0530 (Wed, 05 Nov 2014)" );
	script_name( "Windows Services Stop" );
	script_tag( name: "summary", value: "If the windows services started manually by nasl
  then stop those services before exit." );
	script_category( ACT_END );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_mandatory_keys( "RemoteRegistry/Win/Service/Manual/Start" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
if(!defined_func( "win_cmd_exec" )){
	exit( 0 );
}
func run_command( command, password, username ){
	var command, password, username, serQueryRes, serStat;
	serQueryRes = win_cmd_exec( cmd: command, password: password, username: username );
	if( ContainsString( serQueryRes, "Access is denied" ) ){
		error_message( data: "SC Command Error: Access is denied." );
	}
	else {
		if( ContainsString( serQueryRes, "The specified service does not exist" ) ){
			error_message( data: "SC Command Error: The specified service does not exist." );
		}
		else {
			if( ContainsString( serQueryRes, "The service cannot be started" ) && ContainsString( serQueryRes, "it is disabled" ) ){
				error_message( data: "SC Command Error: Unable to start the service, maybe it is set to 'Disabled'." );
			}
			else {
				if( ContainsString( serQueryRes, "OpenService FAILED" ) && ContainsString( serQueryRes, "specified service does not exist" ) ){
					error_message( data: "SC Command Error: The Specified Service does not Exit." );
				}
				else {
					if( ContainsString( serQueryRes, "StartService FAILED" ) ){
						error_message( data: "SC Command Error: Failed to start the service." );
					}
					else {
						if( ContainsString( serQueryRes, "An instance of the service is already running" ) ){
							error_message( data: "SC Command Error: An instance of the service is already running." );
						}
						else {
							if(ContainsString( serQueryRes, "SERVICE_NAME" ) && ContainsString( serQueryRes, "STATE" ) && ContainsString( serQueryRes, "SERVICE_EXIT_CODE" )){
								serStat = eregmatch( pattern: "STATE.*: [0-9]  ([a-zA-Z_]+)", string: serQueryRes );
								return serStat[1];
							}
						}
					}
				}
			}
		}
	}
}
username = kb_smb_login();
password = kb_smb_password();
if(!username && !password){
	exit( 0 );
}
domain = kb_smb_domain();
if(domain){
	username = domain + "/" + username;
}
service_kb_list = get_kb_list( "*/Win/Service/Manual/Start" );
if(!service_kb_list){
	exit( 0 );
}
for service_kb in keys( service_kb_list ) {
	service = split( buffer: service_kb, sep: "/", keep: FALSE );
	if(service[0]){
		cmd = "cmd /c sc query " + service[0];
		serQueryStat = run_command( command: cmd, password: password, username: username );
		if(ContainsString( serQueryStat, "RUNNING" )){
			cmd = "cmd /c sc stop " + service[0];
			serQueryStat = run_command( command: cmd, password: password, username: username );
			if(ContainsString( serQueryStat, "STOP_PENDING" )){
				cmd = "cmd /c sc query " + service[0];
				serQueryStat = run_command( command: cmd, password: password, username: username );
				if(!ContainsString( serQueryStat, "STOPPED" )){
					error_message( data: "SC Command Error: Failed to stop the service: " + service[0] );
				}
			}
		}
	}
}
exit( 0 );

