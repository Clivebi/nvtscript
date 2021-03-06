if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96107" );
	script_version( "$Revision: 11470 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-19 11:45:56 +0200 (Wed, 19 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2010-06-10 15:20:25 +0200 (Thu, 10 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_name( "IT-Grundschutz: List reject Rule on Cisco Voip Devices over Telnet" );
	script_add_preference( name: "Telnet Testuser Name", type: "entry", value: "UserName" );
	script_add_preference( name: "Telnet Testuser Password", type: "password", value: "PassWord" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "ssh_authorization.sc" );
	script_tag( name: "summary", value: "This plugin list reject Rule on Cisco Voip Devices over Telnet.
  To use this test, you must configure Username and password for this test in the preferences." );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("default_account.inc.sc");
telnet_port = get_kb_item( "Services/telnet" );
if(!telnet_port){
	telnet_port = 23;
}
login = script_get_preference( "Telnet Testuser Name" );
password = script_get_preference( "Telnet Testuser Password" );
if(!login || login == "UserName" || login == "" || !password || password == "PassWord" || password == ""){
	set_kb_item( name: "GSHB/Voice", value: "no credentials set" );
	exit( 0 );
}
soc = open_sock_tcp( telnet_port );
if(!soc){
	telnet_port = 0;
	set_kb_item( name: "GSHB/Voice", value: "error" );
	set_kb_item( name: "GSHB/Voice/log", value: "no Telnet Port" );
	exit( 0 );
}
ret = telnet_negotiate( socket: soc, pattern: "(ogin:|asscode:|assword:)" );
if(strlen( ret )){
	if(stridx( ret, "sername:" ) != -1 || stridx( ret, "ogin:" ) != -1){
		send( socket: soc, data: NASLString( login, "\\r\\n" ) );
		ret = recv_until( socket: soc, pattern: "(assword:|asscode:)" );
	}
	if(stridx( ret, "assword:" ) == -1 && stridx( ret, "asscode:" ) == -1){
		close( soc );
		return ( 0 );
	}
	send( socket: soc, data: NASLString( password, "\\r\\n" ) );
	r = recv( socket: soc, length: 4096 );
	send( socket: soc, data: NASLString( "term len 0\\r\\n" ) );
	r2 = recv_until( socket: soc, pattern: "(assword:|asscode:|ogin:|% Bad password)" );
	if( !r2 ){
		send( socket: soc, data: NASLString( "\r\nshow version  | include Cisco\r\n" ) );
		cisco = recv( socket: soc, length: 16384 );
		send( socket: soc, data: NASLString( "\r\nshow version  | include oice\r\n" ) );
		voice = recv( socket: soc, length: 16384 );
		send( socket: soc, data: NASLString( "\r\nshow running-config | include (R|r)ule .* (R|r)eject\r\n" ) );
		transla = recv( socket: soc, length: 16384 );
	}
	else {
		set_kb_item( name: "GSHB/Voice", value: "Login Failed" );
		close( soc );
		exit( 0 );
	}
	close( soc );
}
val = split( buffer: cisco, sep: "\r\n", keep: 0 );
for(i = 0;i < max_index( val );i++){
	if(val[i] == "" || IsMatchRegexp( val[i], ".*#$" ) || val[i] == "show version" || IsMatchRegexp( val[i], ".*#show version" )){
		continue;
	}
	retcisco += val[i] + "\n";
}
val = split( buffer: voice, sep: "\r\n", keep: 0 );
for(i = 0;i < max_index( val );i++){
	if(val[i] == "" || IsMatchRegexp( val[i], ".*#$" ) || val[i] == "show version  | include oice" || IsMatchRegexp( val[i], ".*#show version  | include oice" )){
		continue;
	}
	retvoice += val[i] + "\n";
}
val = split( buffer: transla, sep: "\r\n", keep: 0 );
for(i = 0;i < max_index( val );i++){
	if(val[i] == "" || IsMatchRegexp( val[i], ".*#$" ) || val[i] == "show running-config | include (R|r)ule .* (R|r)eject" || IsMatchRegexp( val[i], ".*#show running-config | include (R|r)ule .* (R|r)eject" )){
		continue;
	}
	rettransla += val[i] + "\n";
}
if( !retvoice ){
	set_kb_item( name: "GSHB/Voice", value: "novoice" );
	exit( 0 );
}
else {
	if( ContainsString( voice, "show: command not found" ) ){
		set_kb_item( name: "GSHB/Voice", value: "nocisco" );
		exit( 0 );
	}
	else {
		if( !retcisco ){
			set_kb_item( name: "GSHB/Voice", value: "nocisco" );
			exit( 0 );
		}
		else {
			if(!rettransla){
				rettransla = "noconfig";
			}
			if(!retacl){
				retacl = "noconfig";
			}
		}
	}
}
set_kb_item( name: "GSHB/Voice", value: "Cisco-Voice" );
set_kb_item( name: "GSHB/Voice/translation", value: rettransla );
exit( 0 );

