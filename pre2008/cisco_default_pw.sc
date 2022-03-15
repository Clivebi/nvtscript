if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.23938" );
	script_version( "2019-08-30T13:00:30+0000" );
	script_tag( name: "last_modification", value: "2019-08-30 13:00:30 +0000 (Fri, 30 Aug 2019)" );
	script_tag( name: "creation_date", value: "2007-11-04 00:32:20 +0100 (Sun, 04 Nov 2007)" );
	script_cve_id( "CVE-1999-0508" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Cisco default password" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2001 - 2006 Javier Fernandez-Sanguino and Renaud Deraison" );
	script_family( "CISCO" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23, "Services/ssh", 22 );
	script_mandatory_keys( "ssh_or_telnet/banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_add_preference( name: "Use complete password list (not only vendor specific passwords)", type: "checkbox", value: "no" );
	script_tag( name: "solution", value: "Change the default password." );
	script_tag( name: "summary", value: "The remote CISCO router has a default password set. This allows an attacker
  to get a lot information about the network, and possibly to shut it down if the 'enable' password is not set
  either or is also a default password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("default_account.inc.sc");
require("default_credentials.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
ssh_port = 0;
func check_cisco_telnet( login, password, port ){
	soc = open_sock_tcp( port );
	if(!soc){
		telnet_port = 0;
		return;
	}
	msg = telnet_negotiate( socket: soc, pattern: "(ogin:|asscode:|assword:)" );
	if(strlen( msg )){
		if(stridx( msg, "sername:" ) != -1 || stridx( msg, "ogin:" ) != -1){
			send( socket: soc, data: NASLString( login, "\\r\\n" ) );
			msg = recv_until( socket: soc, pattern: "(assword:|asscode:)" );
		}
		if(isnull( msg ) || ( stridx( msg, "assword:" ) == -1 && stridx( msg, "asscode:" ) == -1 )){
			close( soc );
			return 0;
		}
		send( socket: soc, data: NASLString( password, "\\r\\n" ) );
		r = recv( socket: soc, length: 4096 );
		send( socket: soc, data: NASLString( "show ver\\r\\n" ) );
		r = recv_until( socket: soc, pattern: "(Cisco (Internetwork Operating System|IOS) Software|assword:|asscode:|ogin:|% Bad password)" );
		if(ContainsString( r, "Cisco Internetwork Operating System Software" ) || ContainsString( r, "Cisco IOS Software" ) || IsMatchRegexp( r, "IOS(-| )X(E|R)" )){
			report = "It was possible to log in as \'" + login + "\'/\'" + password + "\'\n";
			security_message( port: port, data: report );
			close( soc );
			exit( 0 );
		}
		close( soc );
	}
}
func check_cisco_account( login, password ){
	var port, ret, banner, soc, res;
	if(( ssh_port && get_port_state( ssh_port ) ) && !isnull( login )){
		soc = open_sock_tcp( ssh_port );
		if( soc ){
			ret = ssh_login( socket: soc, login: login, password: password );
			if( ret == 0 ){
				r = ssh_cmd( socket: soc, cmd: "show ver", timeout: 60, nosh: TRUE );
				if(ContainsString( r, "Cisco Internetwork Operating System Software" ) || ContainsString( r, "Cisco IOS Software" ) || IsMatchRegexp( r, "IOS(-| )X(E|R)" )){
					report = "It was possible to log in as \'" + login + "\'/\'" + password + "\'\n";
					security_message( port: ssh_port, data: report );
					close( soc );
					exit( 0 );
				}
				close( soc );
			}
			else {
				close( soc );
				return 0;
			}
		}
		else {
			ssh_port = 0;
		}
	}
	if(telnet_port && get_port_state( telnet_port )){
		if(isnull( password )){
			password = "";
		}
		if(!telnet_checked){
			banner = telnet_get_banner( port: telnet_port );
			if(banner == NULL){
				telnet_port = 0;
				return 0;
			}
			if(stridx( banner, "User Access Verification" ) == -1 && stridx( banner, "assword:" ) == -1){
				telnet_port = 0;
				return 0;
			}
			telnet_checked++;
		}
		check_cisco_telnet( login: login, password: password, port: telnet_port );
	}
	return 0;
}
ssh_port = get_kb_item( "Services/ssh" );
if(!ssh_port){
	ssh_port = 22;
}
telnet_port = get_kb_item( "Services/telnet" );
if(!telnet_port){
	telnet_port = 23;
}
telnet_checked = 0;
check_cisco_account( login: "cisco", password: "cisco" );
check_cisco_account( login: "", password: "" );
p = script_get_preference( "Use complete password list (not only vendor specific passwords)" );
if( ContainsString( p, "yes" ) ){
	clist = try();
}
else {
	clist = try( vendor: "cisco" );
}
if(!clist){
	exit( 0 );
}
if(!safe_checks()){
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
		check_cisco_account( login: user, password: pass );
	}
}
exit( 0 );

