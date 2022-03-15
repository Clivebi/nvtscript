if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17638" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0508" );
	script_name( "Avaya P330 Stackable Switch found with default password" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Charles Thier" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/avaya_p330/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_add_preference( name: "Use complete password list (not only vendor specific passwords)", type: "checkbox", value: "no" );
	script_tag( name: "solution", value: "Telnet to this switch and change the default password." );
	script_tag( name: "summary", value: "The remote host appears to be an Avaya P330 Stackable Switch with its default password set." );
	script_tag( name: "impact", value: "The attacker could use this default password to gain remote access
  to your switch. This password could also be potentially used to
  gain other sensitive information about your network from the switch." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("default_credentials.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "Welcome to P330" )){
	exit( 0 );
}
p = script_get_preference( "Use complete password list (not only vendor specific passwords)" );
if( ContainsString( p, "yes" ) ){
	clist = try();
}
else {
	clist = try( vendor: "avaya" );
}
if(!clist){
	exit( 0 );
}
for credential in clist {
	credential = str_replace( string: credential, find: "\\;", replace: "#sem_legacy#" );
	credential = str_replace( string: credential, find: "\\:", replace: "#sem_new#" );
	user_pass = split( buffer: credential, sep: ":", keep: FALSE );
	if(isnull( user_pass[0] ) || isnull( user_pass[1] )){
		user_pass = split( buffer: credential, sep: ";", keep: FALSE );
		if(isnull( user_pass[0] ) || isnull( user_pass[1] )){
			continue;
		}
	}
	user = chomp( user_pass[0] );
	pass = chomp( user_pass[1] );
	user = str_replace( string: user, find: "#sem_legacy#", replace: ";" );
	pass = str_replace( string: pass, find: "#sem_legacy#", replace: ";" );
	user = str_replace( string: user, find: "#sem_new#", replace: ":" );
	pass = str_replace( string: pass, find: "#sem_new#", replace: ":" );
	if(tolower( pass ) == "none"){
		pass = "";
	}
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	answer = recv( socket: soc, length: 4096 );
	if(ContainsString( answer, "ogin:" )){
		send( socket: soc, data: NASLString( user, "\\r\\n" ) );
		answer = recv( socket: soc, length: 4096 );
		send( socket: soc, data: NASLString( pass, "\\r\\n" ) );
		answer = recv( socket: soc, length: 4096 );
		if(ContainsString( answer, "Password accepted" )){
			security_message( port: port, data: "It was possible to login with the credentials '" + user + ":" + pass + "'." );
		}
	}
	close( soc );
}
exit( 0 );

