if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10988" );
	script_version( "2021-01-20T08:41:35+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 08:41:35 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Netware NDS Object Enumeration" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Digital Defense, Inc" );
	script_family( "General" );
	script_dependencies( "gb_netware_core_protocol_detect.sc" );
	script_require_ports( "Services/ncp", 524 );
	script_mandatory_keys( "netware/ncp/detected" );
	script_tag( name: "solution", value: "The NDS object PUBLIC should not have Browse rights the tree should
  be restricted to authenticated users only.

  Removing Browse rights from the object will fix this issue. If this is an external system it is
  recommended that access to port 524 is blocked from the Internet." );
	script_tag( name: "summary", value: "This host is a Novell Netware (eDirectory) server, and has browse
  rights on the PUBLIC object." );
	script_tag( name: "impact", value: "It is possible to enumerate all NDS objects, including users, with
  crafted queries. An attacker can use this to gain information about this host." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 524, proto: "ncp" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
nds_seq_num = raw_string( 0x00 );
server_name = "";
nds_tree_name = "";
nds_object_name = "";
report = "";
report_users = "";
first = 1;
conn_create = raw_string( 0x44, 0x6d, 0x64, 0x54, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, ord( nds_seq_num ), 0xff, 0x01, 0xff, 0x04 );
send( socket: soc, data: conn_create );
r = recv( socket: soc, length: 4096 );
if( ContainsString( r, "tNcP" ) ){
	conn_number_low = 1;
	conn_number_high = 1;
	conn_number_low = r[11];
	conn_number_high = r[13];
	nds_seq_num = raw_string( ord( nds_seq_num ) + 1 );
	server_info_req = raw_string( 0x44, 0x6d, 0x64, 0x54, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x80, 0x22, 0x22, ord( nds_seq_num ), ord( conn_number_low ), 0x01, ord( conn_number_high ), 0x17, 0x00, 0x01, 0x11 );
	send( socket: soc, data: server_info_req );
	r = recv( socket: soc, length: 4096 );
	if(ContainsString( r, "tNcP" )){
		for(i = 16;i < 63;i++){
			if(ord( r[i] ) != 0){
				server_name = NASLString( server_name, r[i] );
			}
		}
		report = NASLString( "Server Name: ", server_name, "\\n" );
	}
	nds_seq_num = raw_string( ord( nds_seq_num ) + 1 );
	nds_ping_req = raw_string( 0x44, 0x6d, 0x64, 0x54, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x22, 0x22, ord( nds_seq_num ), ord( conn_number_low ), 0x01, ord( conn_number_high ), 0x68, 0x01, 0x00, 0x00, 0x00 );
	send( socket: soc, data: nds_ping_req );
	r = recv( socket: soc, length: 4096 );
	if(ContainsString( r, "tNcP" )){
		for(i = 24;i < 45;i++){
			if( ( ContainsString( "_", r[i] ) ) && ( ContainsString( "_", r[i + 1] ) ) ){
				}
			else {
				nds_tree_name = NASLString( nds_tree_name, r[i] );
			}
		}
		report = NASLString( report, "NDS Tree Name: ", nds_tree_name, "\\n" );
	}
	nds_object_id = raw_string( 0xff, 0xff, 0xff, 0xff );
	for(;!( ContainsString( raw_string( 0xfc ), r[14] ) );){
		nds_seq_num = raw_string( ord( nds_seq_num ) + 1 );
		nds_user_req = raw_string( 0x44, 0x6d, 0x64, 0x54, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x39, 0x22, 0x22, ord( nds_seq_num ), ord( conn_number_low ), 0x04, ord( conn_number_high ), 0x17, 0x00, 0x09, 0x37, ord( nds_object_id[0] ), ord( nds_object_id[1] ), ord( nds_object_id[2] ), ord( nds_object_id[3] ), 0x00, 0x01, 0x01, 0x2a );
		send( socket: soc, data: nds_user_req );
		r = recv( socket: soc, length: 4096 );
		if(( ContainsString( r, "tNcP" ) ) && ( !( ContainsString( raw_string( 0xfc ), r[14] ) ) )){
			nds_object_id = raw_string( ord( r[16] ), ord( r[17] ), ord( r[18] ), ord( r[19] ) );
			nds_object_name = "";
			for(i = 22;i < 71;i++){
				if( ord( r[i] ) == 0 ){
					}
				else {
					nds_object_name = NASLString( nds_object_name, r[i] );
				}
			}
			if( first == 1 ){
				report_users = NASLString( report_users, nds_object_name );
				first = 0;
			}
			else {
				report_users = NASLString( report_users, ", ", nds_object_name );
			}
		}
	}
	close( soc );
	if(strlen( report ) > 0){
		if(strlen( report_users ) > 0){
			report = NASLString( report, "NDS Users: ", report_users );
		}
		report = "It was possible to gather the following information about the remote host:\n\n" + report;
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
else {
	close( soc );
	exit( 0 );
}

