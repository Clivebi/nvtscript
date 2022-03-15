if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140050" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-11-03 14:59:49 +0100 (Thu, 03 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OPC-UA Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 4840 );
	script_tag( name: "summary", value: "This script performs detection of OPC-UA Servers." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("byte_func.inc.sc");
func openSecureChannelReqRes( socket ){
	var socket, opc_req_header, opc_req_footer, recv, result;
	opc_req_header = raw_string( "OPN", "F" );
	opc_req_footer = raw_string( 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, "http://opcfoundation.org/UA/SecurityPolicy#None", 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xbe, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xee, 0x36, 0x00 );
	l = ( strlen( opc_req_header ) + strlen( opc_req_footer ) + 4 );
	len = mkdword( l );
	opc_req = opc_req_header + len + opc_req_footer;
	send( socket: socket, data: opc_req );
	recv = recv( socket: socket, length: 512 );
	return recv;
}
func createSessionReqRes( socket, channelId, endpoinurl, timestamp ){
	var socket, channelId, endpointurl, epu_len, sessid_len, authToken, opc_req_header, opc_req_footer, recv, result, timestamp;
	epu_len = mkdword( strlen( endpointurl ) );
	opc_req_header = raw_string( "MSG", "F" );
	opc_req_footer = raw_string( channelId, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0xcd, 0x01, 0x00, 0x00, timestamp, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x75, 0x72, 0x6e, 0x3a, 0x66, 0x72, 0x65, 0x65, 0x6f, 0x70, 0x63, 0x75, 0x61, 0x3a, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x1e, 0x00, 0x00, 0x00, 0x75, 0x72, 0x6e, 0x3a, 0x66, 0x72, 0x65, 0x65, 0x6f, 0x70, 0x63, 0x75, 0x61, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x69, 0x6f, 0x3a, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x02, 0x12, 0x00, 0x00, 0x00, 0x50, 0x75, 0x72, 0x65, 0x20, 0x50, 0x79, 0x74, 0x68, 0x6f, 0x6e, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, epu_len, endpointurl, 0x1b, 0x00, 0x00, 0x00, 0x50, 0x75, 0x72, 0x65, 0x20, 0x50, 0x79, 0x74, 0x68, 0x6f, 0x6e, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x31, 0x20, 0x00, 0x00, 0x00, 0xc8, 0x5b, 0x29, 0x74, 0x4a, 0x25, 0xac, 0xc7, 0x28, 0x6a, 0xe5, 0xcf, 0x76, 0xa8, 0xd1, 0x82, 0xbc, 0x55, 0xe4, 0x88, 0x1d, 0x26, 0xf6, 0xe9, 0x9a, 0x6c, 0x25, 0x9a, 0x26, 0x95, 0x89, 0xa6, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x40, 0x77, 0x4b, 0x41, 0x00, 0x00, 0x00, 0x00 );
	l = ( strlen( opc_req_header ) + strlen( opc_req_footer ) + 4 );
	len = mkdword( l );
	opc_req = opc_req_header + len + opc_req_footer;
	send( socket: socket, data: opc_req );
	recv = recv( socket: socket, length: 8 );
	recv_len = getword( blob: recv, pos: 4 );
	recv = recv( socket: socket, length: recv_len );
	result = hexstr( substr( recv, 33, 36 ) );
	if(result != "00000000" || recv_len < 69){
		return FALSE;
	}
	sessid_len = ord( recv[44] );
	if( sessid_len == 1 ) {
		pos = 48;
	}
	else {
		if( sessid_len == 2 ) {
			pos = 51;
		}
		else {
			if(sessid_len == 4){
				pos = 63;
			}
		}
	}
	authtoken_len = ord( recv[pos] );
	if( authtoken_len == 4 ) {
		authToken = substr( recv, pos, pos + 18 );
	}
	else {
		if( authtoken_len == 1 ) {
			authToken = substr( recv, pos, pos + 3 );
		}
		else {
			if( authtoken_len == 2 ) {
				authToken = substr( recv, pos, pos + 6 );
			}
			else {
				if( authtoken_len == 5 ) {
					authToken = substr( recv, pos, pos + 38 );
				}
				else {
					return FALSE;
				}
			}
		}
	}
	return authToken;
}
func activateSessionReqRes( socket, channelId, authtoken, timestamp ){
	var socket, channelId, authtoken, opc_req_header, opc_req_footer, recv, timestamp, result;
	opc_req_header = raw_string( "MSG", "F" );
	opc_req_footer = raw_string( channelId, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0xd3, 0x01, authtoken, timestamp, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x65, 0x6e, 0x01, 0x00, 0x41, 0x01, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff );
	l = ( strlen( opc_req_header ) + strlen( opc_req_footer ) + 4 );
	len = mkdword( l );
	opc_req = opc_req_header + len + opc_req_footer;
	send( socket: socket, data: opc_req );
	recv = recv( socket: socket, length: 512 );
	if(strlen( recv ) < 43){
		return FALSE;
	}
	result = hexstr( substr( recv, 40, 43 ) );
	if(result != "00000000"){
		return FALSE;
	}
	return TRUE;
}
func readReqRes( socket, channelId, authtoken, timestamp ){
	var socket, channelId, authtoken, opc_req_header, opc_req_footer, recv, timestamp, result;
	opc_req_header = raw_string( "MSG", "F" );
	opc_req_footer = raw_string( channelId, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x77, 0x02, authtoken, timestamp, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0xd0, 0x08, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff );
	l = ( strlen( opc_req_header ) + strlen( opc_req_footer ) + 4 );
	len = mkdword( l );
	opc_req = opc_req_header + len + opc_req_footer;
	send( socket: socket, data: opc_req );
	recv = recv( socket: socket, length: 1024 );
	if(strlen( recv ) < 43){
		return FALSE;
	}
	result = hexstr( substr( recv, 40, 43 ) );
	if(result != "00000000"){
		return FALSE;
	}
	return recv;
}
port = unknownservice_get_port( default: 4840 );
host = get_host_name();
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
opc_req_header = raw_string( "HEL", "F" );
EndPointUrl = "opc.tcp://" + host + ":" + port;
epu_len = strlen( EndPointUrl );
epu_len = mkdword( epu_len );
opc_req_footer = raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, epu_len, EndPointUrl );
l = ( strlen( opc_req_header ) + strlen( opc_req_footer ) + 4 );
len = mkdword( l );
opc_req = opc_req_header + len + opc_req_footer;
send( socket: soc, data: opc_req );
recv = recv( socket: soc, length: 4 );
if(strlen( recv ) != 4 || ( !IsMatchRegexp( recv, "^ACKF" ) && !IsMatchRegexp( recv, "^ERRF" ) )){
	close( soc );
	exit( 0 );
}
set_kb_item( name: "opcua/detected", value: TRUE );
service_register( port: port, proto: "opc-ua" );
if(data = openSecureChannelReqRes( socket: soc )){
	if(strlen( data ) < 122){
		break;
	}
	result = hexstr( substr( data, 119, 122 ) );
	if(result != "00000000"){
		break;
	}
	timestamp = substr( data, 107, 114 );
	secChannelId = substr( data, 32, 35 );
	if(auth_token = createSessionReqRes( socket: soc, channelId: secChannelId, endpointurl: EndPointUrl, timestamp: timestamp )){
		if(activateSessionReqRes( socket: soc, channelId: secChannelId, authtoken: auth_token, timestamp: timestamp )){
			if(data = readReqRes( socket: soc, channelId: secChannelId, authtoken: auth_token, timestamp: timestamp )){
				len = getword( blob: data, pos: 87 );
				pos = 91;
				product_uri = substr( data, pos, pos + len - 1 );
				pos += len;
				len = getword( blob: data, pos: pos );
				pos += 4;
				manufacturer = substr( data, pos, pos + len - 1 );
				set_kb_item( name: "opcua/manufacturer", value: manufacturer );
				pos += len;
				len = getword( blob: data, pos: pos );
				pos += 4;
				product_name = substr( data, pos, pos + len - 1 );
				set_kb_item( name: "opcua/product_name", value: product_name );
				pos += len;
				len = getword( blob: data, pos: pos );
				pos += 4;
				sw_version = substr( data, pos, pos + len - 1 );
				set_kb_item( name: "opcua/version", value: sw_version );
				extra = "\n\nThe following information was extracted:\n\n" + "Product Name:      " + product_name + "\n" + "Manufacturer:      " + manufacturer + "\n" + "Software Version:  " + sw_version + "\n";
				pos += len;
				len = getword( blob: data, pos: pos );
				pos += 4;
				if(len != 0){
					build = substr( data, pos, pos + len - 1 );
					extra += "Build:             " + build;
					set_kb_item( name: "opcua/build", value: build );
				}
			}
		}
	}
}
close( soc );
report = "A OPC-UA Server is running at this port.";
if(extra){
	report += extra;
}
log_message( port: port, data: report );
exit( 0 );

