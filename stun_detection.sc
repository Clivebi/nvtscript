if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11986" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Detect STUN Server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Noam Rathaus" );
	script_family( "Service detection" );
	script_require_udp_ports( "Services/udp/stun", 3478 );
	script_tag( name: "solution", value: "If this service is not needed, disable it or filter incoming traffic
  to this port." );
	script_tag( name: "summary", value: "A VPN server is listening on the remote port.

  Description :

  The remote host is running a STUN (Simple Traversal of User Datagram
  Protocol - RFC 3489) server.

  Simple Traversal of User Datagram Protocol (UDP) Through Network
  Address Translators (NATs) (STUN) is a lightweight protocol that
  allows applications to discover the presence and types of NATs and
  firewalls between them and the public Internet.  It also provides the
  ability for applications to determine the public Internet Protocol
  (IP) addresses allocated to them by the NAT.  STUN works with many
  existing NATs, and does not require any special behavior from them.
  As a result, it allows a wide variety of applications to work through
  existing NAT infrastructure.

  Make sure the use of this software is done in accordance with your corporate
  security policy." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("global_settings.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
debug = debug_level;
port = service_get_port( default: 3478, ipproto: "udp", proto: "stun" );
udpsock = open_sock_udp( port );
if(!udpsock){
	exit( 0 );
}
data = raw_string( 0x00, 0x01, 0x00, 0x08, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 );
send( socket: udpsock, data: data );
response = "";
z = recv( socket: udpsock, length: 1024, min: 1 );
if(z){
	if(debug){
		dump( dtitle: "STUN", ddata: z );
	}
	if(z[0] == raw_string( 0x01 ) && z[1] == raw_string( 0x01 )){
		length = ord( z[2] ) * 256 + ord( z[3] );
		if(debug){
			display( "length: ", length, "\\n" );
		}
		offset = 2 + 2 + 16;
		for(i = 0;i < length;){
			count = 0;
			if(z[i + offset] == raw_string( 0x00 ) && z[i + 1 + offset] == raw_string( 0x01 )){
				count += 2;
				if(z[i + count + offset] == raw_string( 0x00 ) && z[i + count + 1 + offset] == raw_string( 0x08 )){
					count += 2;
					if(z[i + count + 1 + offset] == raw_string( 0x01 )){
						count += 2;
						port = ord( z[i + count + offset] ) * 256 + ord( z[i + count + 1 + offset] );
						ip = NASLString( ord( z[i + count + 2 + offset] ), ".", ord( z[i + count + 3 + offset] ), ".", ord( z[i + count + 4 + offset] ), ".", ord( z[i + count + 5 + offset] ) );
						count += 6;
						response = NASLString( response, "Mapped Address: ", ip, ":", port, "\\n" );
					}
				}
			}
			if(z[i + offset] == raw_string( 0x00 ) && z[i + 1 + offset] == raw_string( 0x04 )){
				count += 2;
				if(z[i + count + offset] == raw_string( 0x00 ) && z[i + count + 1 + offset] == raw_string( 0x08 )){
					count += 2;
					if(z[i + count + 1 + offset] == raw_string( 0x01 )){
						count += 2;
						port = ord( z[i + count + offset] ) * 256 + ord( z[i + count + 1 + offset] );
						ip = NASLString( ord( z[i + count + 2 + offset] ), ".", ord( z[i + count + 3 + offset] ), ".", ord( z[i + count + 4 + offset] ), ".", ord( z[i + count + 5 + offset] ) );
						count += 6;
						response = NASLString( response, "Source Address: ", ip, ":", port, "\\n" );
					}
				}
			}
			if(z[i + offset] == raw_string( 0x00 ) && z[i + 1 + offset] == raw_string( 0x05 )){
				count += 2;
				if(z[i + count + offset] == raw_string( 0x00 ) && z[i + count + 1 + offset] == raw_string( 0x08 )){
					count += 2;
					if(z[i + count + 1 + offset] == raw_string( 0x01 )){
						count += 2;
						port = ord( z[i + count + offset] ) * 256 + ord( z[i + count + 1 + offset] );
						ip = NASLString( ord( z[i + count + 2 + offset] ), ".", ord( z[i + count + 3 + offset] ), ".", ord( z[i + count + 4 + offset] ), ".", ord( z[i + count + 5 + offset] ) );
						count += 6;
						response = NASLString( response, "Changed Address: ", ip, ":", port, "\\n" );
					}
				}
			}
			if(count == 0){
				if(debug){
					display( "z[i(", i, ")+offset(", offset, ")]: ", ord( z[i + offset] ), "\\n" );
				}
				i++;
			}
			i += count;
		}
		if(response){
			desc += "\n\nPlugin output :\n\n" + response;
			log_message( port: port, proto: "udp", data: desc );
			service_register( port: port, proto: "stun", ipproto: "udp" );
			exit( 0 );
		}
	}
}

