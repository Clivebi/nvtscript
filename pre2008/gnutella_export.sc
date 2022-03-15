if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11716" );
	script_version( "2019-04-10T13:42:28+0000" );
	script_tag( name: "last_modification", value: "2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "Misconfigured Gnutella" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 Michel Arboi" );
	script_family( "Remote file access" );
	script_dependencies( "find_service.sc", "gnutella_detect.sc" );
	script_require_ports( "Services/gnutella", 6346 );
	script_tag( name: "solution", value: "Disable this Gnutella servent or configure it correctly." );
	script_tag( name: "summary", value: "The remote host is running the Gnutella servent service.

  It seems that the root directory of the remote host is visible through
  this service. Confidential files might be exported." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
func gnutella_read_data( socket, message ){
	var len, i, r2;
	len = 0;
	for(i = 22;i >= 19;i--){
		len = len * 256 + ord( message[i] );
	}
	if(len > 0){
		r2 = recv( socket: socket, length: len );
	}
	return r2;
}
func gnutella_search( socket, search ){
	var MsgId, Msg, r1, r2;
	MsgId = rand_str( length: 16 );
	Msg = raw_string( MsgId, 128, 1, 0, strlen( search ) + 3, 0, 0, 0, 0, 0, search, 0 );
	send( socket: socket, data: Msg );
	for(;1;){
		r1 = recv( socket: socket, length: 23 );
		if(strlen( r1 ) < 23){
			return;
		}
		r2 = gnutella_read_data( socket: socket, message: r1 );
		if(ord( r1[16] ) == 129 && substr( r1, 0, 15 ) == MsgId){
			return r2;
		}
	}
}
require("misc_func.inc.sc");
port = get_kb_item( "Services/gnutella" );
if(!port){
	port = 6346;
}
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "GNUTELLA CONNECT/0.4\n\n" );
r = recv( socket: soc, length: 13 );
if(r != "GNUTELLA OK\n\n"){
	close( soc );
	exit( 0 );
}
r = recv( socket: soc, length: 23 );
if(strlen( r ) >= 23){
	r2 = gnutella_read_data( socket: soc, message: r );
	if(ord( r[16] ) == 0){
		MsgId = substr( r, 0, 15 );
		ip = this_host();
		x = eregmatch( string: ip, pattern: "([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)" );
		Msg = raw_string( MsgId, 1, 1, 0, 14, 0, 0, 0, 11, 11, int( x[1] ), int( x[2] ), int( x[3] ), int( x[4] ), 1, 1, 0, 0, 1, 1, 0, 0 );
		send( socket: soc, data: Msg );
	}
}
dangerous_file = make_list( "boot.ini",
	 "win.ini",
	 "autoexec.bat",
	 "config.sys",
	 "io.sys",
	 "msdos.sys",
	 "pagefile.sys",
	 "inetd.conf",
	 "host.conf" );
for d in dangerous_file {
	r = gnutella_search( socket: soc, search: d );
	if(!isnull( r ) && ord( r[0] ) > 0){
		close( soc );
		security_message( port: port );
		exit( 0 );
	}
}
close( soc );
exit( 99 );

