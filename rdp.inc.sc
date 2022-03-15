BYTE_ORDER_LITTLE_ENDIAN = 1;
BYTE_ORDER_BIG_ENDIAN = 2;
var RDP_SSL_REQUIRED_BY_SERVER, RDP_SSL_NOT_ALLOWED_BY_SERVER, RDP_SSL_CERT_NOT_ON_SERVER, RDP_INCONSISTENT_FLAGS, RDP_HYBRID_REQUIRED_BY_SERVER, RDP_SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER;
var RDP_PROTOCOL_RDP, RDP_PROTOCOL_SSL, RDP_PROTOCOL_HYBRID, RDP_PROTOCOL_RDSTLS, RDP_PROTOCOL_HYBRID_EX;
var RDP_NEG_PROTOCOL, RDP_NEG_FAILURE;
RDP_SSL_REQUIRED_BY_SERVER = 1;
RDP_SSL_NOT_ALLOWED_BY_SERVER = 2;
RDP_SSL_CERT_NOT_ON_SERVER = 3;
RDP_INCONSISTENT_FLAGS = 4;
RDP_HYBRID_REQUIRED_BY_SERVER = 5;
RDP_SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6;
RDP_PROTOCOL_RDP = 0;
RDP_PROTOCOL_SSL = 1;
RDP_PROTOCOL_HYBRID = 2;
RDP_PROTOCOL_RDSTLS = 4;
RDP_PROTOCOL_HYBRID_EX = 8;
RDP_NEG_PROTOCOL[0] = "RDP_PROTOCOL_RDP";
RDP_NEG_PROTOCOL[1] = "RDP_PROTOCOL_SSL";
RDP_NEG_PROTOCOL[2] = "RDP_PROTOCOL_HYBRID";
RDP_NEG_PROTOCOL[4] = "RDP_PROTOCOL_RDSTLS";
RDP_NEG_PROTOCOL[8] = "RDP_PROTOCOL_HYBRID_EX";
RDP_NEG_FAILURE[1] = "RDP_SSL_REQUIRED_BY_SERVER";
RDP_NEG_FAILURE[2] = "RDP_SSL_NOT_ALLOWED_BY_SERVER";
RDP_NEG_FAILURE[3] = "RDP_SSL_CERT_NOT_ON_SERVER";
RDP_NEG_FAILURE[4] = "RDP_INCONSISTENT_FLAGS";
RDP_NEG_FAILURE[5] = "RDP_HYBRID_REQUIRED_BY_SERVER";
RDP_NEG_FAILURE[6] = "RDP_SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER";
func rdp_build_virtual_channel_pdu_request( flags, data ){
	var flags, data;
	var data_len;
	if(isnull( flags )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#flags#-#rdp_build_virtual_channel_pdu_request" );
		return FALSE;
	}
	if(isnull( data )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#rdp_build_virtual_channel_pdu_request" );
		return FALSE;
	}
	data_len = strlen( data );
	set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
	req = mkdword( data_len ) + mkdword( flags ) + data;
	return req;
}
func rdp_build_data_tpdu( data ){
	var data;
	var tpkt_length, req;
	if(isnull( data )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#rdp_build_data_tpdu" );
		return FALSE;
	}
	tpkt_length = strlen( data ) + 7;
	set_byte_order( BYTE_ORDER_BIG_ENDIAN );
	req = raw_string( 0x03, 0x00 ) + mkword( tpkt_length ) + raw_string( 0x02, 0xf0, 0x80 );
	return req;
}
func rdp_create_pdu_negotiation_request( use_cookie ){
	var use_cookie;
	var vt_strings, cookie, len_cookie, full_length, req;
	if( use_cookie ){
		vt_strings = get_vt_strings();
		cookie = "Cookie: mstshash=" + vt_strings["lowercase_rand"];
		len_cookie = strlen( cookie );
		full_length = 4 + 7 + len_cookie + 2 + 8;
		req = raw_string( 0x03 ) + raw_string( 0x00 ) + raw_string( 0x00 ) + raw_string( full_length ) + raw_string( full_length - 5 ) + raw_string( 0xe0 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00 ) + cookie + raw_string( 0x0d, 0x0a ) + raw_string( 0x01 ) + raw_string( 0x00 ) + raw_string( 0x08, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 );
	}
	else {
		req = raw_string( 0x03 ) + raw_string( 0x00 ) + raw_string( 0x00 ) + raw_string( 0x0b ) + raw_string( 0x06 ) + raw_string( 0xe0 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00 );
	}
	return req;
}
func rdp_create_pdu_connect_initial_request( client_name ){
	var client_name;
	var len, req;
	if(isnull( client_name )){
		client_name = "rdesktop";
	}
	len = strlen( client_name );
	if( strlen( len ) > 15 ) {
		client_name = ascii2unicode( data: substr( client_name, 0, 14 ) );
	}
	else {
		client_name = ascii2unicode( data: substr( client_name, 0, len ) );
	}
	client_name += crap( length: 32 - strlen( client_name ), data: raw_string( 0x00 ) );
	req = raw_string( 0x7f, 0x65 ) + raw_string( 0x82, 0x01, 0xbe ) + raw_string( 0x04, 0x01, 0x01 ) + raw_string( 0x04, 0x01, 0x01 ) + raw_string( 0x01, 0x01, 0xff ) + raw_string( 0x30, 0x20 ) + raw_string( 0x02, 0x02, 0x00, 0x22 ) + raw_string( 0x02, 0x02, 0x00, 0x02 ) + raw_string( 0x02, 0x02, 0x00, 0x00 ) + raw_string( 0x02, 0x02, 0x00, 0x01 ) + raw_string( 0x02, 0x02, 0x00, 0x00 ) + raw_string( 0x02, 0x02, 0x00, 0x01 ) + raw_string( 0x02, 0x02, 0xff, 0xff ) + raw_string( 0x02, 0x02, 0x00, 0x02 ) + raw_string( 0x30, 0x20 ) + raw_string( 0x02, 0x02, 0x00, 0x01 ) + raw_string( 0x02, 0x02, 0x00, 0x01 ) + raw_string( 0x02, 0x02, 0x00, 0x01 ) + raw_string( 0x02, 0x02, 0x00, 0x01 ) + raw_string( 0x02, 0x02, 0x00, 0x00 ) + raw_string( 0x02, 0x02, 0x00, 0x01 ) + raw_string( 0x02, 0x02, 0x04, 0x20 ) + raw_string( 0x02, 0x02, 0x00, 0x02 ) + raw_string( 0x30, 0x20 ) + raw_string( 0x02, 0x02, 0xff, 0xff ) + raw_string( 0x02, 0x02, 0xfc, 0x17 ) + raw_string( 0x02, 0x02, 0xff, 0xff ) + raw_string( 0x02, 0x02, 0x00, 0x01 ) + raw_string( 0x02, 0x02, 0x00, 0x00 ) + raw_string( 0x02, 0x02, 0x00, 0x01 ) + raw_string( 0x02, 0x02, 0xff, 0xff ) + raw_string( 0x02, 0x02, 0x00, 0x02 ) + raw_string( 0x04, 0x82, 0x01, 0x4b ) + raw_string( 0x00, 0x05 ) + raw_string( 0x00, 0x14, 0x7c, 0x00, 0x01 ) + raw_string( 0x81, 0x42 ) + raw_string( 0x00, 0x08, 0x00, 0x10 ) + raw_string( 0x00, 0x01, 0xc0, 0x00 ) + raw_string( 0x44, 0x75, 0x63, 0x61 ) + raw_string( 0x81, 0x34 ) + raw_string( 0x01, 0xc0 ) + raw_string( 0xd8, 0x00 ) + raw_string( 0x04, 0x00, 0x08, 0x00 ) + raw_string( 0x20, 0x03 ) + raw_string( 0x58, 0x02 ) + raw_string( 0x01, 0xca ) + raw_string( 0x03, 0xaa ) + raw_string( 0x09, 0x04, 0x00, 0x00 ) + raw_string( 0x28, 0x0a, 0x00, 0x00 ) + client_name + raw_string( 0x04, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x0c, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x01, 0xca ) + raw_string( 0x01, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x18, 0x00 ) + raw_string( 0x07, 0x00 ) + raw_string( 0x01, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00 ) + raw_string( 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x04, 0xc0 ) + raw_string( 0x0c, 0x00 ) + raw_string( 0x09, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x02, 0xc0 ) + raw_string( 0x0c, 0x00 ) + raw_string( 0x03, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x03, 0xc0 ) + raw_string( 0x44, 0x00 ) + raw_string( 0x05, 0x00, 0x00, 0x00 ) + raw_string( 0x63, 0x6c, 0x69, 0x70 ) + raw_string( 0x72, 0x64, 0x72, 0x00 ) + raw_string( 0xc0, 0xa0, 0x00, 0x00 ) + raw_string( 0x4d, 0x53, 0x5f, 0x54 ) + raw_string( 0x31, 0x32, 0x30, 0x00 ) + raw_string( 0x80, 0x80, 0x00, 0x00 ) + raw_string( 0x72, 0x64, 0x70, 0x73 ) + raw_string( 0x6e, 0x64, 0x00, 0x00 ) + raw_string( 0xc0, 0x00, 0x00, 0x00 ) + raw_string( 0x73, 0x6e, 0x64, 0x64 ) + raw_string( 0x62, 0x67, 0x00, 0x00 ) + raw_string( 0xc0, 0x00, 0x00, 0x00 ) + raw_string( 0x72, 0x64, 0x70, 0x64 ) + raw_string( 0x72, 0x00, 0x00, 0x00 ) + raw_string( 0x80, 0x80, 0x00, 0x00 );
	req = rdp_build_data_tpdu( data: req ) + req;
	return req;
}
func rdp_create_pdu_erect_domain_request(  ){
	var req;
	req = raw_string( 0x04 ) + raw_string( 0x01, 0x00 ) + raw_string( 0x01, 0x00 );
	req = rdp_build_data_tpdu( data: req ) + req;
	return req;
}
func rdp_create_pdu_attach_user_request(  ){
	var req;
	req = raw_string( 0x28 );
	req = rdp_build_data_tpdu( data: req ) + req;
	return req;
}
func rdp_create_pdu_channel_request( user1, channel_id, debug ){
	var user1, channel_id, debug;
	var req;
	if(isnull( user1 )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#user1#-#rdp_create_pdu_channel_request" );
		return FALSE;
	}
	if(isnull( channel_id )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#channel_id#-#rdp_create_pdu_channel_request" );
		return FALSE;
	}
	if(debug){
		display( "-- rdp_create_pdu_channel_request --\\nChosen userid:\\n", hexdump( ddata: user1 ), "\\nChosen channel_id: ", channel_id );
	}
	req = raw_string( 0x38 ) + user1 + dec2hex( num: channel_id );
	req = rdp_build_data_tpdu( data: req ) + req;
	return req;
}
func rdp_create_pdu_security_exchange( client_rand, public_exponent, modulus, bitlen ){
	var client_rand, public_exponent, modulus, bitlen;
	var enc, userdata_len, userdata_len_low, userdata_len_high, flags;
	var pkt_len, reverse_bitlen, req;
	if(isnull( client_rand )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#client_rand#-#rdp_create_pdu_security_exchange" );
		return FALSE;
	}
	if(isnull( public_exponent )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#public_exponent#-#rdp_create_pdu_security_exchange" );
		return FALSE;
	}
	if(isnull( modulus )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#modulus#-#rdp_create_pdu_security_exchange" );
		return FALSE;
	}
	if(isnull( bitlen )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#bitlen#-#rdp_create_pdu_security_exchange" );
		return FALSE;
	}
	client_rand = reverse_blob( blob: client_rand );
	enc = rsa_public_encrypt( data: client_rand, e: public_exponent, n: modulus, pad: "FALSE" );
	enc = reverse_blob( blob: enc );
	bitlen += 8;
	userdata_len = bitlen + 8;
	userdata_len_low = dec2hex( num: userdata_len & 0xff );
	userdata_len_high = userdata_len / 256;
	flags = dec2hex( num: 0x80 | userdata_len_high );
	pkt_len = userdata_len + 15;
	set_byte_order( BYTE_ORDER_BIG_ENDIAN );
	reverse_bitlen = reverse_blob( blob: mkdword( bitlen ) );
	req = raw_string( 0x64 ) + raw_string( 0x00, 0x08 ) + raw_string( 0x03, 0xeb ) + raw_string( 0x70 ) + flags + userdata_len_low + raw_string( 0x01, 0x00 ) + raw_string( 0x00, 0x00 ) + reverse_bitlen + enc + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
	req = rdp_build_data_tpdu( data: req ) + req;
	return req;
}
func rdp_create_pdu_client_info_request( user_name, domain_name, ip_addr ){
	var user_name, domain_name, ip_addr;
	var vt_strings, username_len, domain_name_len, ip_addr_len, req;
	if(!user_name){
		vt_strings = get_vt_strings();
		user_name = vt_strings["ping_string"];
	}
	user_name = substr( user_name, 0, 20 );
	user_name = ascii2unicode( data: user_name );
	user_name_len = strlen( user_name );
	if(!domain_name){
		vt_strings = get_vt_strings();
		domain_name = vt_strings["ping_string"];
	}
	domain_name = substr( domain_name, 0, 24 );
	domain_name = ascii2unicode( data: domain_name );
	domain_name_len = strlen( domain_name );
	if(!ip_addr){
		ip_addr = this_host();
	}
	ip_addr = ascii2unicode( data: ip_addr ) + raw_string( 0x00, 0x00 );
	ip_addr_len = strlen( ip_addr );
	set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
	req = raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x33, 0x01, 0x00, 0x00 ) + mkword( domain_name_len ) + mkword( user_name_len ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( domain_name ) + raw_string( 0x00, 0x00 ) + raw_string( user_name ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x02, 0x00 ) + mkword( ip_addr_len ) + raw_string( ip_addr ) + raw_string( 0x3c, 0x00 ) + raw_string( 0x3c, 0x00, 0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x4e, 0x00, 0x54, 0x00, 0x5c, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5c, 0x00, 0x6d, 0x00, 0x73, 0x00, 0x74, 0x00, 0x73, 0x00, 0x63, 0x00, 0x61, 0x00, 0x78, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x00, 0x00 ) + raw_string( 0xa4, 0x01, 0x00, 0x00 ) + raw_string( 0x47, 0x00, 0x54, 0x00, 0x42, 0x00, 0x2c, 0x00, 0x20, 0x00, 0x6e, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x74, 0x00, 0x69, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x47, 0x00, 0x54, 0x00, 0x42, 0x00, 0x2c, 0x00, 0x20, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74, 0x00, 0x69, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0xc4, 0xff, 0xff, 0xff ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x27, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00 );
	return req;
}
func rdp_build_share_control_header( type, data ){
	var type, data;
	var total_len, req;
	total_len = strlen( data ) + 6;
	set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
	req = mkword( total_len ) + mkword( type ) + raw_string( 0xf1, 0x03 ) + data;
	return req;
}
func rdp_build_share_data_header( type, data ){
	var type, data;
	var uncompressed_len, req;
	uncompressed_len = strlen( data ) + 4;
	set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
	req = raw_string( 0xea, 0x03, 0x01, 0x00 ) + raw_string( 0x00 ) + raw_string( 0x01 ) + mkword( uncompressed_len ) + dec2hex( num: type ) + raw_string( 0x00 ) + raw_string( 0x00, 0x00 ) + data;
	return req;
}
func rdp_build_pdu_client_control_cooperate(  ){
	var pdu, data_header;
	pdu = raw_string( 0x04, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 );
	data_header = rdp_build_share_data_header( type: 0x14, data: pdu );
	return rdp_build_share_control_header( type: 0x17, data: data_header );
}
func rdp_create_pdu_client_control_request(  ){
	var pdu, data_header;
	pdu = raw_string( 0x01, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 );
	data_header = rdp_build_share_data_header( type: 0x14, data: pdu );
	return rdp_build_share_control_header( type: 0x17, data: data_header );
}
func rdp_create_pdu_client_font_list_request(  ){
	var pdu, data_header;
	pdu = raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x03, 0x00 ) + raw_string( 0x32, 0x00 );
	data_header = rdp_build_share_data_header( type: 0x27, data: pdu );
	return rdp_build_share_control_header( type: 0x17, data: data_header );
}
func rdp_create_pdu_client_synchronize_request( target_user ){
	var target_user;
	var pdu, data_header;
	if(isnull( target_user )){
		target_user = 0;
	}
	set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
	pdu = raw_string( 0x01, 0x00 ) + mkword( target_user );
	data_header = rdp_build_share_data_header( type: 0x1f, data: pdu );
	return rdp_build_share_control_header( type: 0x17, data: data_header );
}
func rdp_create_pdu_client_confirm_active_request(  ){
	var pdu;
	pdu = raw_string( 0xea, 0x03, 0x01, 0x00 ) + raw_string( 0xea, 0x03 ) + raw_string( 0x06, 0x00 ) + raw_string( 0x8e, 0x01 ) + raw_string( 0x4d, 0x53, 0x54, 0x53, 0x43, 0x00 ) + raw_string( 0x0e, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x01, 0x00 ) + raw_string( 0x18, 0x00 ) + raw_string( 0x01, 0x00, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x04, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x02, 0x00 ) + raw_string( 0x1c, 0x00 ) + raw_string( 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x03, 0x58, 0x02, 0x00, 0x00, 0x01, 0x00 ) + raw_string( 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 ) + raw_string( 0x03, 0x00 ) + raw_string( 0x58, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x47, 0x01, 0x2a, 0x00 ) + raw_string( 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0xa1, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0xe4, 0x04, 0x00, 0x00, 0x13, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x03, 0x78, 0x00, 0x00, 0x00 ) + raw_string( 0x78, 0x00, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x08, 0x00 ) + raw_string( 0x0a, 0x00 ) + raw_string( 0x01, 0x00, 0x14, 0x00, 0x14, 0x00 ) + raw_string( 0x0a, 0x00 ) + raw_string( 0x08, 0x00 ) + raw_string( 0x06, 0x00, 0x00, 0x00 ) + raw_string( 0x07, 0x00 ) + raw_string( 0x0c, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x05, 0x00 ) + raw_string( 0x0c, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00 ) + raw_string( 0x09, 0x00 ) + raw_string( 0x08, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x0f, 0x00 ) + raw_string( 0x08, 0x00 ) + raw_string( 0x01, 0x00, 0x00, 0x00 ) + raw_string( 0x0d, 0x00 ) + raw_string( 0x58, 0x00 ) + raw_string( 0x01, 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x0c, 0x00 ) + raw_string( 0x08, 0x00 ) + raw_string( 0x01, 0x00, 0x00, 0x00 ) + raw_string( 0x0e, 0x00 ) + raw_string( 0x08, 0x00 ) + raw_string( 0x01, 0x00, 0x00, 0x00 ) + raw_string( 0x10, 0x00 ) + raw_string( 0x34, 0x00 ) + raw_string( 0xfe, 0x00, 0x04, 0x00, 0xfe, 0x00, 0x04, 0x00, 0xfe, 0x00, 0x08, 0x00, 0xfe, 0x00, 0x08, 0x00 ) + raw_string( 0xfe, 0x00, 0x10, 0x00, 0xfe, 0x00, 0x20, 0x00, 0xfe, 0x00, 0x40, 0x00, 0xfe, 0x00, 0x80, 0x00 ) + raw_string( 0xfe, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00 );
	return rdp_build_share_control_header( type: 0x13, data: pdu );
}
func rdp_create_pdu_client_input_event_sychronize_request(  ){
	var pdu, data_header;
	pdu = raw_string( 0x01, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00 ) + raw_string( 0x00, 0x00, 0x00, 0x00 );
	data_header = rdp_build_share_data_header( type: 0x1c, data: pdu );
	return rdp_build_share_control_header( type: 0x17, data: data_header );
}
func rdp_parse_serverdata( data, debug ){
	var data, debug;
	var len, rdp_package, pos, header_type, header_length, security_header;
	var server_random, public_exponent, rsa_magic, bitlen, modulus, ret_array;
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#rdp_parse_serverdata" );
		return FALSE;
	}
	len = strlen( data );
	if(len < 256){
		return NULL;
	}
	rdp_package = substr( data, 73, len );
	pos = 0;
	for(;pos < strlen( rdp_package );){
		header_type = rdp_package[pos] + rdp_package[pos + 1];
		if(debug){
			display( "Header-Type: ", hexdump( ddata: header_type ) );
		}
		header_length = getword( blob: rdp_package[pos + 3] + rdp_package[pos + 2] );
		if(debug){
			display( "Header-Length: ", header_length );
		}
		if(header_type == raw_string( 0x02, 0x0c )){
			security_header = TRUE;
			if(debug){
				display( "Security header received" );
			}
			server_random = substr( rdp_package, pos + 20, pos + 51 );
			if(debug){
				display( "Server Random:\\n", hexdump( ddata: server_random ) );
			}
			public_exponent = substr( rdp_package, pos + 84, pos + 87 );
			if(debug){
				display( "Server Exponent:\\n", hexdump( ddata: public_exponent ) );
			}
			rsa_magic = substr( rdp_package, pos + 68, pos + 71 );
			if(debug){
				display( "RSA magic:\\n", hexdump( ddata: rsa_magic ) );
			}
			if(rsa_magic != "RSA1"){
				if(debug){
					display( "Unsupported RSA magic received, only RSA1 is currently supported." );
				}
				return NULL;
			}
			bitlen = getdword( blob: rdp_package[pos + 75] + rdp_package[pos + 74] + rdp_package[pos + 73] + rdp_package[pos + 72] ) - 8;
			if(debug){
				display( "RSA bitlen:\\n", bitlen );
			}
			modulus = substr( rdp_package, pos + 88, pos + 87 + bitlen );
			if(debug){
				display( "Server Modulus:\\n", hexdump( ddata: modulus ) );
			}
		}
		pos += header_length;
	}
	if(!security_header){
		return NULL;
	}
	ret_array["server_random"] = server_random;
	ret_array["public_exponent"] = reverse_blob( blob: public_exponent );
	ret_array["modulus"] = reverse_blob( blob: modulus );
	ret_array["rsa_magic"] = rsa_magic;
	ret_array["bitlen"] = bitlen;
	return ret_array;
}
func rdp_build_pkt( data, channel_id, client_info, rdp_sec, enc_data, hmackey ){
	var data, channel_id, client_info, rdp_sec, enc_data, hmackey;
	var flags, pdu, user_data_len, udl_with_flag, req;
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#rdp_build_pkt" );
		return FALSE;
	}
	if(!enc_data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#enc_data#-#rdp_build_pkt" );
		return FALSE;
	}
	if(!hmackey){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#hmackey#-#rdp_build_pkt" );
		return FALSE;
	}
	if(isnull( client_info )){
		client_info = FALSE;
	}
	if(isnull( rdp_sec )){
		rdp_sec = TRUE;
	}
	flags = 0;
	if(rdp_sec){
		flags = flags | 8;
	}
	if(client_info){
		flags = flags | 64;
	}
	set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
	flags = mkword( flags );
	if(!channel_id){
		channel_id = raw_string( 0x03, 0xeb );
	}
	pdu = "";
	if(client_info || rdp_sec){
		pdu += flags;
		pdu += raw_string( 0x00, 0x00 );
	}
	if( rdp_sec ){
		pdu += substr( rdp_hmac( mac_salt_key: hmackey, data_content: data ), 0, 7 );
		pdu += enc_data;
	}
	else {
		pdu += data;
	}
	user_data_len = strlen( pdu );
	udl_with_flag = dec2hex( num: 0x8000 | user_data_len );
	req = raw_string( 0x64 ) + raw_string( 0x00, 0x08 ) + channel_id + raw_string( 0x70 ) + udl_with_flag + pdu;
	req = rdp_build_data_tpdu( data: req ) + req;
	return req;
}
func rdp_hmac( mac_salt_key, data_content ){
	var mac_salt_key, data_content;
	var pad1, pad2, data_len, sha1, md5;
	pad1 = crap( data: raw_string( 0x36 ), length: 40 );
	pad2 = crap( data: raw_string( 0x5c ), length: 48 );
	set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
	data_len = mkdword( strlen( data_content ) );
	sha1 = SHA1( mac_salt_key + pad1 + data_len + data_content );
	md5 = MD5( mac_salt_key + pad2 + sha1 );
	return md5;
}
func rdp_salted_hash( s_bytes, i_bytes, client_rand, server_rand ){
	var s_bytes, i_bytes, client_rand, server_rand;
	var input, sha1;
	input = i_bytes + s_bytes + client_rand + server_rand;
	sha1 = SHA1( input );
	input = s_bytes + sha1;
	return MD5( input );
}
func rdp_final_hash( k, client_rand, server_rand ){
	var k, client_rand, server_rand;
	return MD5( k + client_rand + server_rand );
}
func rdp_calculate_rc4_keys( client_rand, server_rand, debug ){
	var client_rand, server_rand, debug;
	var pre_master_secret, master_secret, sess_key_blob;
	var initial_client_decryptkey_128, initial_client_encryptkey_128, mac_key, ret_array;
	if(!client_rand){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#client_rand#-#rdp_calculate_rc4_keys" );
		return FALSE;
	}
	if(!server_rand){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#server_rand#-#rdp_calculate_rc4_keys" );
		return FALSE;
	}
	pre_master_secret = substr( client_rand, 0, 23 ) + substr( server_rand, 0, 23 );
	master_secret = rdp_salted_hash( s_bytes: pre_master_secret, i_bytes: "A", client_rand: client_rand, server_rand: server_rand ) + rdp_salted_hash( s_bytes: pre_master_secret, i_bytes: "BB", client_rand: client_rand, server_rand: server_rand ) + rdp_salted_hash( s_bytes: pre_master_secret, i_bytes: "CCC", client_rand: client_rand, server_rand: server_rand );
	sess_key_blob = rdp_salted_hash( s_bytes: master_secret, i_bytes: "X", client_rand: client_rand, server_rand: server_rand ) + rdp_salted_hash( s_bytes: master_secret, i_bytes: "YY", client_rand: client_rand, server_rand: server_rand ) + rdp_salted_hash( s_bytes: master_secret, i_bytes: "ZZZ", client_rand: client_rand, server_rand: server_rand );
	initial_client_decryptkey_128 = rdp_final_hash( k: substr( sess_key_blob, 16, 31 ), client_rand: client_rand, server_rand: server_rand );
	initial_client_encryptkey_128 = rdp_final_hash( k: substr( sess_key_blob, 32, 47 ), client_rand: client_rand, server_rand: server_rand );
	mac_key = substr( sess_key_blob, 0, 15 );
	ret_array["initial_client_encryptkey_128"] = initial_client_encryptkey_128;
	ret_array["initial_client_decryptkey_128"] = initial_client_decryptkey_128;
	ret_array["mac_key"] = mac_key;
	ret_array["sess_key_blob"] = sess_key_blob;
	if(debug){
		display( "-- rdp_calculate_rc4_keys --" );
		display( "RC4_ENC_KEY:\\n", hexstr( ret_array["initial_client_encryptkey_128"] ) );
		display( "RC4_DEC_KEY:\\n", hexstr( ret_array["initial_client_decryptkey_128"] ) );
		display( "HMAC_KEY:\\n", hexstr( ret_array["mac_key"] ) );
		display( "SESS_BLOB\\n", hexstr( ret_array["sess_key_blob"] ), "\\n" );
	}
	return ret_array;
}
func rdp_create_client_random(  ){
	var i, client_rand;
	for(i = 0;i < 32;i++){
		client_rand += raw_string( rand() % 256 );
	}
	return client_rand;
}
func rdp_create_disconnect_req(  ){
	var req;
	req = raw_string( 0x21 ) + raw_string( 0x80 );
	req = rdp_build_data_tpdu( data: req ) + req;
	return req;
}
func rdp_send( socket, data, debug, debug_req_name ){
	var socket, data, debug, debug_req_name;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#rdp_send" );
		return FALSE;
	}
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#rdp_send" );
		return FALSE;
	}
	if(debug){
		display( "-- rdp_send --" );
		if(debug_req_name){
			display( "Sending ", debug_req_name );
		}
		display( "Sending packet length: ", strlen( data ) );
		display( "Sending packet:\\n", hexdump( ddata: data ), "\\n" );
	}
	send( socket: socket, data: data );
}
func rdp_send_recv( socket, data, debug, debug_req_name ){
	var socket, data, debug, debug_req_name;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#rdp_send_recv" );
		return FALSE;
	}
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#rdp_send_recv" );
		return FALSE;
	}
	rdp_send( socket: socket, data: data, debug: debug, debug_req_name: debug_req_name );
	return rdp_recv( socket: socket, debug: debug, debug_req_name: debug_req_name );
}
func rdp_recv( socket, debug, debug_req_name ){
	var socket, debug, debug_req_name;
	var header, hd_len, buf, len;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#rdp_recv" );
		return FALSE;
	}
	header = recv( socket: socket, length: 4 );
	hd_len = strlen( header );
	if(hd_len != 4 || !IsMatchRegexp( hexstr( header ), "^0300" )){
		if(debug){
			display( "-- rdp_recv --" );
			if( debug_req_name ) {
				display( "Received malformed header response to ", debug_req_name, "\\n" );
			}
			else {
				display( "Received malformed header response\\n" );
			}
			if( hd_len > 0 ){
				display( "Received header length: ", hd_len );
				display( "Received header packet:\\n", hexdump( ddata: header ), "\\n" );
			}
			else {
				display( "Received empty header\\n" );
			}
		}
		return FALSE;
	}
	len = getword( blob: header, pos: 2 );
	buf = recv( socket: socket, length: len - 4 );
	buf = header + buf;
	if(debug){
		display( "-- rdp_recv --" );
		if(debug_req_name){
			display( "Received response to ", debug_req_name );
		}
		display( "Received packet length: ", len );
		display( "Received packet:\\n", hexdump( ddata: buf ), "\\n" );
	}
	return buf;
}

