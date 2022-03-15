if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18373" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Detect slident and/or fake identd" );
	script_family( "Service detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_dependencies( "find_service1.sc", "secpod_open_tcp_ports.sc" );
	script_require_ports( "Services/auth", 113 );
	script_mandatory_keys( "TCP/PORTS" );
	script_tag( name: "summary", value: "The remote ident server returns random token instead of
  leaking real user IDs. This is a good thing." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
iport = service_get_port( default: 113, proto: "auth" );
port = tcp_get_first_open_port();
if(!port || port == 139 || port == 445){
	port = iport;
}
j = 0;
os_reported = FALSE;
for(i = 0;i < 3;i++){
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	req = strcat( port, ",", get_source_port( soc ), "\r\n" );
	isoc = open_sock_tcp( iport );
	if(!isoc){
		close( soc );
		continue;
	}
	send( socket: isoc, data: req );
	res = recv_line( socket: isoc, length: 1024 );
	res = chomp( res );
	if(IsMatchRegexp( res, "^[0-9]+ ?, ?[0-9]+" ) && !ContainsString( res, "USERID" )){
		res2 = recv_line( socket: isoc, length: 1024 );
		res2 = chomp( res2 );
		if(res2){
			res += res2;
		}
	}
	if(res && ContainsString( res, "USERID" )){
		ids = split( buffer: res, sep: ":", keep: FALSE );
		if(max_index( ids ) > 2){
			os = chomp( ids[2] );
			os = ereg_replace( string: os, pattern: "^(\\s+)", replace: "" );
			id = chomp( ids[3] );
			id = ereg_replace( string: id, pattern: "^(\\s+)", replace: "" );
			if(strlen( id )){
				got_id[j++] = id;
			}
			if(os && !egrep( string: os, pattern: "^[0-9]+$" ) && !os_reported){
				set_kb_item( name: "ident/os_banner/available", value: TRUE );
				os_reported = TRUE;
				replace_kb_item( name: "ident/" + iport + "/os_banner/full", value: res );
				replace_kb_item( name: "ident/" + iport + "/os_banner/os_only", value: os );
			}
		}
	}
}
slident = 0;
if( j == 1 ){
	if(IsMatchRegexp( got_id[0], "^[a-f0-9]{32}$" )){
		slident = 1;
	}
}
else {
	for(i = 1;i < j;i++){
		if(got_id[i - 1] != got_id[i]){
			slident = 1;
			break;
		}
	}
}
if(slident){
	log_message( port: iport, data: "A service supporting the Identification Protocol (ident) seems to be running on this port." );
	service_register( port: iport, proto: "auth", message: "A service supporting the Identification Protocol (ident) seems to be running on this port." );
	set_kb_item( name: "fake_identd/" + iport, value: TRUE );
}

