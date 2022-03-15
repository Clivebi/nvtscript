if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11201" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Nortel/Bay Networks/Xylogics Annex default password" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Douglas Minderhout" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/nortel_bay_networks/annex/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Telnet to this terminal server change to the root user with 'su' and
  set the password with the 'passwd' command. Then, go to the admin mode using the
  'admin' command. Cli security can then be enabled by setting the vcli_security to
  'Y' with the command 'set annex vcli_security Y'. This will require ERPCD or RADIUS
  authentication for access to the terminal server. Changes can then be applied through
  the 'reset annex all' command." );
	script_tag( name: "summary", value: "The remote terminal server has the default password set.
  This means that anyone who has (downloaded) a user manual can
  telnet to it and gain administrative access." );
	script_tag( name: "impact", value: "If modems are attached to this terminal server, it may allow
  unauthenticated remote access to the network." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
func myrecv( socket, pattern ){
	var socket, pattern;
	for(;1;){
		r = recv_line( socket: socket, length: 1024 );
		if(strlen( r ) == 0){
			return ( 0 );
		}
		if(ereg( pattern: pattern, string: r )){
			return ( r );
		}
	}
}
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "Annex" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = telnet_negotiate( socket: soc );
nudge = NASLString( "\\r\\n" );
send( socket: soc, data: nudge );
resp = recv( socket: soc, length: 1024 );
if(ContainsString( resp, "NetLogin:" ) || ContainsString( resp, "Login:" )){
	close( soc );
	exit( 0 );
}
if(ContainsString( resp, "Annex" )){
	test = NASLString( "cli\\r\\n" );
	send( socket: soc, data: test );
	resp = myrecv( socket: soc, pattern: ".*annex:.*" );
	if(ContainsString( resp, "annex:" )){
		report = NASLString( "CLI Security is disabled on the Annex" );
		security_message( port: port, data: report );
		test = NASLString( "su\\r\\n" );
		send( socket: soc, data: test );
		resp = myrecv( socket: soc, pattern: ".*assword:.*" );
		if(ContainsString( resp, "assword:" )){
			ip = get_host_ip();
			test = NASLString( ip, "\\r\\n" );
			send( socket: soc, data: test );
			resp = myrecv( socket: soc, pattern: ".*annex#.*" );
			if(ContainsString( resp, "annex#" )){
				report = NASLString( "The SuperUser password is at it's default setting." );
				security_message( port: port, data: report );
			}
		}
	}
	close( soc );
}
exit( 99 );

