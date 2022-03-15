if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11327" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Nortel Baystack switch password test" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Douglas Minderhout" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/nortel_networks/baystack/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Telnet to this switch and set passwords under 'Console/Comm Port Configuration' for both
  read only and read write. Then, set the parameter 'Console Switch Password' or 'Console Stack Password'
  to 'Required for TELNET' or 'Required for Both'." );
	script_tag( name: "summary", value: "The remote switch has a weak password." );
	script_tag( name: "impact", value: "This means that anyone who has (downloaded) a user manual can telnet to it and gain
  administrative access." );
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
	for(;1;){
		r = recv_line( socket: soc, length: 1024 );
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
if(!banner || ( !ContainsString( banner, "Ctrl-Y" ) && !ContainsString( banner, "P Configuration" ) )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = telnet_negotiate( socket: soc );
if(ContainsString( buf, "NetLogin:" ) || ContainsString( buf, "Login:" )){
	close( soc );
	exit( 0 );
}
if( ContainsString( buf, "Ctrl-Y" ) ){
	test = raw_string( 0x19, 0xF0 );
	send( socket: soc, data: test );
	resp = recv( socket: soc, length: 1024 );
	if( ContainsString( resp, "P Configuration" ) ){
		report = NASLString( "There is no password assigned to the remote Baystack switch." );
		close( soc );
		security_message( port: port, data: report );
		exit( 0 );
	}
	else {
		if(ContainsString( resp, "asswor" )){
			test = NASLString( "secure\\r" );
			send( socket: soc, data: test );
			resp = recv( socket: soc, length: 1024 );
			if( ContainsString( resp, "P Configuration" ) ){
				report = NASLString( "The default password 'secure' is assigned to the remote Baystack switch." );
				close( soc );
				security_message( port: port, data: report );
				exit( 0 );
			}
			else {
				if(ContainsString( resp, "asswor" )){
					test = NASLString( "user\\r" );
					send( socket: soc, data: test );
					resp = recv( socket: soc, length: 1024 );
					if(ContainsString( resp, "P Configuration" )){
						report = NASLString( "The default password 'user' is assigned to the remote Baystack switch." );
						close( soc );
						security_message( port: port, data: report );
						exit( 0 );
					}
				}
			}
		}
	}
}
else {
	if(ContainsString( buf, "P Configuration" )){
		report = NASLString( "There is no password assigned to the remote Baystack switch. This switch is most likely using a very old version of software. It would be best to contact Nortel for an upgrade." );
		close( soc );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
close( soc );
exit( 99 );

