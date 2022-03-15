BYTE_ORDER_LITTLE_ENDIAN = 1;
BYTE_ORDER_BIG_ENDIAN = 2;
func dtls_create_client_hello( version, random, seq_num, cookie ){
	var version, random, seq_num, cookie;
	var dtls_header, handshake_proto, fragment;
	var data_len, data, cookie_len;
	if(isnull( version )){
		version = "DTLS10";
	}
	if(isnull( random )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#random#-#dtls_create_client_hello" );
		return NULL;
	}
	if(isnull( seq_num )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#seq_num#-#dtls_create_client_hello" );
		return NULL;
	}
	set_byte_order( BYTE_ORDER_BIG_ENDIAN );
	if( version == "DTLS10" ) {
		version = raw_string( 0xfe, 0xff );
	}
	else {
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#dtls_create_client_hello(): Unsupported DTLS Version" );
		return NULL;
	}
	if( isnull( cookie ) || cookie == "" ) {
		cookie_len = 0;
	}
	else {
		cookie_len = strlen( cookie );
	}
	fragment = raw_string( version, random, 0x00, mkbyte( cookie_len ) );
	if(!isnull( cookie ) || cookie != ""){
		fragment = raw_string( fragment, cookie );
	}
	fragment = raw_string( fragment, 0x00, 0x10, sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"], sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"], sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA"], sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"], sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"], sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA"], sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CBC_SHA"], sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CBC_SHA"], 0x01, 0x00, 0x00, 0x24, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, ec_point_formats["ansiX962_compressed_prime"], ec_point_formats["ansiX962_compressed_char2"], 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, elliptic_curves["x25519"], elliptic_curves["secp256r1"], elliptic_curves["x448"], elliptic_curves["secp521r1"], elliptic_curves["secp521r1"], 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00 );
	handshake_proto = raw_string( 0x01, 0x00, mkword( strlen( fragment ) ), mkword( seq_num ), 0x00, 0x00, 0x00, 0x00, mkword( strlen( fragment ) ) );
	data = handshake_proto + fragment;
	data_len = strlen( data );
	dtls_header = raw_string( 0x16, version, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, mkbyte( seq_num ), mkword( data_len ) );
	return dtls_header + data;
}
func dtls_client_hello( socket ){
	var socket;
	var seq_num, version, rand, cookie_len, hello1, hello2;
	var cookie, recv;
	if(isnull( socket )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#dtls_client_hello" );
		return NULL;
	}
	set_byte_order( BYTE_ORDER_BIG_ENDIAN );
	seq_num = 0;
	version = "DTLS10";
	rand = dec2hex( num: unixtime() ) + rand_str( length: 28 );
	cookie_len = 0;
	hello1 = dtls_create_client_hello( version: version, random: rand, seq_num: seq_num );
	if(isnull( hello1 )){
		return NULL;
	}
	send( socket: socket, data: hello1 );
	recv = recv( socket: socket, length: 1024, min: 14 );
	if(!recv || strlen( recv ) < 13){
		return NULL;
	}
	if(ord( recv[13] ) == 21){
		return -1;
	}
	if(strlen( recv ) < 27 || ord( recv[13] ) != 3){
		return NULL;
	}
	cookie_len = ord( recv[27] );
	if(strlen( recv ) < 27 + cookie_len){
		return NULL;
	}
	cookie = substr( recv, 28, 28 + cookie_len - 1 );
	seq_num += 1;
	hello2 = dtls_create_client_hello( version: version, random: rand, seq_num: seq_num, cookie: cookie );
	if(isnull( hello2 )){
		return NULL;
	}
	send( socket: socket, data: hello2 );
	recv = recv( socket: socket, length: 1024 );
	if(!recv || strlen( recv ) < 13){
		return NULL;
	}
	if(ord( recv[13] ) == 21){
		return -1;
	}
	if(!recv || strlen( recv ) < 13 || ord( recv[13] ) != 2){
		return NULL;
	}
	return seq_num + 1;
}
func dtls_send_alert( socket, seq_num ){
	var socket, sec_num, version, msg;
	if(isnull( socket )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#dtls_send_alert" );
		return NULL;
	}
	if(isnull( seq_num )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#seq_num#-#dtls_send_alert" );
		return NULL;
	}
	version = raw_string( 0xfe, 0xff );
	msg = raw_string( 0x15, version, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, mkbyte( seq_num ), 0x00, 0x07, 0x02, 0x00, crap( length: 5 ) );
	send( socket: socket, data: msg );
	recv( socket: socket, length: 14 );
	return;
}

