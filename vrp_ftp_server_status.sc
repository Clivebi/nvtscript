if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150245" );
	script_version( "2021-08-24T08:31:17+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 08:31:17 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-14 10:58:06 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Read ftp server status" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "Get the current FTP server configuration of the VRP device.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
if(!get_kb_item( "huawei/vrp/detected" )){
	set_kb_item( name: "Policy/vrp/installed/ERROR", value: TRUE );
	exit( 0 );
}
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/vrp/ssh/ERROR", value: TRUE );
	exit( 0 );
}
cmd = "display ftp-server";
ret = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE );
if(!ret){
	set_kb_item( name: "Policy/vrp/ftpserver/ERROR", value: TRUE );
	exit( 0 );
}
if(IsMatchRegexp( ret, "ftp\\s+server\\s+is\\s+running" )){
	set_kb_item( name: "Policy/vrp/ftpserver/serverstate", value: "Enabled" );
}
for line in split( buffer: ret, keep: FALSE ) {
	key_value = eregmatch( string: line, pattern: "(.+)\\s+:\\s*(.*)" );
	if(key_value){
		key = str_replace( string: chomp( key_value[1] ), find: " ", replace: "" );
		if(!key){
			continue;
		}
		set_kb_item( name: "Policy/vrp/ftpserver/" + tolower( key ), value: key_value[2] );
	}
}
exit( 0 );

