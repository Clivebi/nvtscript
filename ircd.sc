if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11156" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "IRC Server Banner Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "find_service2.sc" );
	script_require_ports( "Services/irc", 6667, 6697, 7697 );
	script_tag( name: "summary", value: "This script tries to detect the banner of an IRC server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
ports = service_get_ports( default_port_list: make_list( 6667,
	 6697,
	 7697 ), proto: "irc" );
host = get_host_name();
for port in ports {
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	final_banner = "";
	host_banner = "";
	nick = NULL;
	blocked = FALSE;
	for(i = 0;i < 9;i++){
		nick += raw_string( 0x41 + ( rand() % 10 ) );
	}
	user = nick;
	req = NASLString( "NICK ", nick, "\\r\\n", "USER ", nick, " ", this_host_name(), " ", host, " :", user, "\\r\\n" );
	send( socket: soc, data: req );
	for(;a = recv_line( socket: soc, length: 4096 );){
		n++;
		if( IsMatchRegexp( a, "^PING." ) ){
			a = ereg_replace( pattern: "PING", replace: "PONG", string: a );
			send( socket: soc, data: a );
		}
		else {
			if( IsMatchRegexp( a, "^ERROR :Closing Link" ) || IsMatchRegexp( a, "^ERROR :Your host is trying to" ) || IsMatchRegexp( a, "^ERROR :Trying to reconnect too fast" ) ){
				close( soc );
				set_kb_item( name: "ircd/detected", value: TRUE );
				log_message( port: port, data: "Unable to get the version of this service due to the error:\n\n" + a );
				service_register( port: port, proto: "irc", message: "An IRC server seems to be running on this port." );
				blocked = TRUE;
				break;
			}
			else {
				if(IsMatchRegexp( a, "^:.* :Your host is .*, running version " )){
					host_banner = a;
				}
			}
		}
		if(n > 256){
			break;
		}
	}
	if(blocked){
		continue;
	}
	send( socket: soc, data: NASLString( "VERSION\\r\\n" ) );
	v = "x";
	for(;( v ) && !ContainsString( v, " 351 " );){
		v = recv_line( socket: soc, length: 256 );
	}
	send( socket: soc, data: NASLString( "QUIT\\r\\n" ) );
	close( soc );
	if(( !v || !IsMatchRegexp( v, "^:.* 351 " ) ) && !IsMatchRegexp( host_banner, "^:.* :Your host is .*, running version " )){
		continue;
	}
	if( v && IsMatchRegexp( v, "^:.* 351 " ) ){
		final_banner = chomp( v );
	}
	else {
		if( host_banner && IsMatchRegexp( host_banner, "^:.* :Your host is .*, running version " ) ){
			final_banner = chomp( host_banner );
		}
		else {
			continue;
		}
	}
	service_register( port: port, proto: "irc", message: "An IRC server seems to be running on this port." );
	set_kb_item( name: "irc/banner/" + port, value: final_banner );
	set_kb_item( name: "ircd/detected", value: TRUE );
	set_kb_item( name: "ircd/banner", value: TRUE );
	log_message( port: port, data: "The IRC server banner is:\n\n" + final_banner );
	continue;
}

