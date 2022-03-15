if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10666" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "AppleShare IP / Apple Filing Protocol (AFP) Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2005 James W. Abendschan <jwa@jammed.com>" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 548 );
	script_tag( name: "summary", value: "The remote host is running an AppleShare IP / Apple Filing Protocol (AFP)
  service.

  By sending a DSIGetStatus request on tcp port 548, it was possible to disclose information about the remote host." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
func b2dw( a, b, c, d ){
	var a, b, c, d;
	var a1, b1, c1, dword;
	a1 = a * 256 * 256 * 256;
	b1 = b * 256 * 256;
	c1 = c * 256;
	dword = a1 + b1 + c1 + d;
	return ( dword );
}
func b2w( low, high ){
	var low, high;
	var word;
	word = high * 256;
	word = word + low;
	return ( word );
}
func pstring( offset, packet ){
	var offset, packet;
	var plen, i, pstr;
	plen = ord( packet[offset] );
	pstr = "";
	for(i = 1;i < plen + 1;i = i + 1){
		pstr = pstr + packet[offset + i];
	}
	return ( pstr );
}
func pluck_counted( offset, packet ){
	var offset, packet;
	var count, str, plucked, count_offset, j;
	count = ord( packet[offset] );
	str = "";
	plucked = "";
	count_offset = offset + 1;
	for(j = 0;j < count;j = j + 1){
		str = pstring( offset: count_offset, packet: packet );
		count_offset = count_offset + strlen( str ) + 1;
		plucked += str;
		if(j < count - 1){
			plucked += "/";
		}
	}
	return ( plucked );
}
func parse_FPGetSrvrInfo( packet, port ){
	var packet, port;
	var machinetype_offset, machinetype, afpversioncount_offset, versions;
	var uamcount_offset, uams, servername, report;
	machinetype_offset = b2w( low: ord( packet[17] ), high: ord( packet[16] ) ) + 16;
	machinetype = pstring( offset: machinetype_offset, packet: packet );
	afpversioncount_offset = b2w( low: ord( packet[19] ), high: ord( packet[18] ) ) + 16;
	versions = pluck_counted( offset: afpversioncount_offset, packet: packet );
	uamcount_offset = b2w( low: ord( packet[21] ), high: ord( packet[20] ) ) + 16;
	uams = pluck_counted( offset: uamcount_offset, packet: packet );
	servername = pstring( offset: 26, packet: packet );
	report = NASLString( "This host is running an AppleShare IP / Apple Filing Protocol (AFP) service.\\n\\n", "Machine type: ", machinetype, "\\n", "Server name:  ", servername, "\\n", "UAMs:         ", uams, "\\n", "AFP Versions: ", versions, "\\n" );
	if(ContainsString( uams, "No User Authen" )){
		report += "\nThe remote service allows the \"guest\" user to connect.";
	}
	if(ContainsString( uams, "Cleartxt Passwrd" )){
		report += "\nThe remote service allows \"Cleartext\" connections.";
		set_kb_item( name: "asip_afp/" + port + "/iscleartext", value: TRUE );
		set_kb_item( name: "asip_afp/iscleartext", value: TRUE );
	}
	log_message( port: port, data: report );
	service_register( port: port, proto: "appleshare" );
	if(machinetype){
		set_kb_item( name: "asip_afp/" + port + "/banner", value: machinetype );
		set_kb_item( name: "asip_afp/banner/available", value: TRUE );
	}
	if(uams){
		set_kb_item( name: "asip_afp/" + port + "/uams", value: uams );
		set_kb_item( name: "asip_afp/uams/available", value: TRUE );
	}
	if(servername){
		set_kb_item( name: "asip_afp/" + port + "/servername", value: servername );
		set_kb_item( name: "asip_afp/servername/available", value: TRUE );
		if(defined_func( "resolve_host_name" ) && defined_func( "add_host_name" )){
			if(resolve_host_name( hostname: servername )){
				add_host_name( hostname: servername, source: "AppleShare IP / Apple Filing Protocol (AFP) Service" );
			}
		}
	}
}
func parse_DSIGetStatus( packet, port ){
	var packet, port;
	var flags, cmd, reqidL, reqidH, reqid, edo, datalen, reserved;
	flags = ord( packet[0] );
	cmd = ord( packet[1] );
	reqidL = ord( packet[2] );
	reqidH = ord( packet[3] );
	reqid = b2w( low: reqidL, high: reqidH );
	if(!( reqid == 57005 )){
		exit( 0 );
	}
	edo = b2dw( a: ord( packet[4] ), b: ord( packet[5] ), c: ord( packet[6] ), d: ord( packet[7] ) );
	datalen = b2dw( a: ord( packet[8] ), b: ord( packet[9] ), c: ord( packet[10] ), d: ord( packet[11] ) );
	reserved = b2dw( a: ord( packet[12] ), b: ord( packet[13] ), c: ord( packet[14] ), d: ord( packet[15] ) );
	if(!( cmd == 3 )){
		exit( 0 );
	}
	return ( parse_FPGetSrvrInfo( packet: packet, port: port ) );
}
func send_DSIGetStatus( sock ){
	var sock;
	var packet, buf;
	packet = raw_string( 0x00, 0x03, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
	send( socket: sock, data: packet );
	buf = recv( socket: sock, length: 8192, timeout: 30 );
	if(strlen( buf ) == 0){
		exit( 0 );
	}
	return ( buf );
}
func asip_status( port ){
	var port;
	var s, packet;
	s = open_sock_tcp( port );
	if(s){
		packet = send_DSIGetStatus( sock: s );
		if(strlen( packet ) > 17){
			parse_DSIGetStatus( packet: packet, port: port );
		}
		close( s );
	}
}
port = 548;
if(service_is_unknown( port: port ) && get_port_state( port )){
	asip_status( port: port );
}

