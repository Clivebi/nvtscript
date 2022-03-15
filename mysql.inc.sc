var ER_HOST_IS_BLOCKED, ER_HOST_NOT_PRIVILEGED;
ER_HOST_IS_BLOCKED = 1129;
ER_HOST_NOT_PRIVILEGED = 1130;
func mysql_recv_server_handshake( socket ){
	var socket;
	var buf, plen;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#mysql_recv_server_handshake" );
		exit( 0 );
	}
	buf = recv( socket: socket, length: 4 );
	if(!buf || strlen( buf ) != 4){
		close( socket );
		exit( 0 );
	}
	plen = ord( buf[0] ) + ( ord( buf[1] ) / 8 ) + ( ord( buf[2] ) / 16 );
	if(ord( buf[3] ) != 0 && ord( buf[3] ) != 1){
		close( socket );
		exit( 0 );
	}
	buf = recv( socket: socket, length: plen );
	if(strlen( buf ) != plen){
		close( socket );
		exit( 0 );
	}
	return buf;
}
func mysql_send_packet( socket, data, seq_id ){
	var socket, data, seq_id;
	var len, packet;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#mysql_send_packet" );
		exit( 0 );
	}
	if(isnull( data )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#mysql_send_packet" );
		close( socket );
		exit( 0 );
	}
	if(isnull( seq_id )){
		seq_id = 1;
	}
	len = strlen( data );
	packet = raw_string( len & 0xff, ( len >> 8 ) & 0xff, ( len >> 16 ) & 0xff ) + mkbyte( seq_id ) + data;
	send( socket: socket, data: packet );
	return len + 4;
}
func mysql_recv_packet( socket ){
	var socket;
	var ret_arr, res, len;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#mysql_recv_packet" );
		exit( 0 );
	}
	ret_arr["err"] = FALSE;
	ret_arr["errno"] = 0;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#mysql_recv_packet" );
		exit( 0 );
	}
	res = recv( socket: socket, length: 4 );
	if(!res || strlen( res ) < 4){
		return;
	}
	len = ord( res[0] ) + ( ord( res[1] ) / 8 ) + ( ord( res[2] ) / 16 );
	ret_arr["pkt_len"] = len;
	ret_arr["pkt_seqid"] = ord( res[3] );
	res = recv( socket: socket, length: len );
	if(!res || strlen( res ) < len){
		return;
	}
	if(hexstr( res[0] ) == "ff"){
		ret_arr["err"] = TRUE;
		ret_arr["errno"] = ord( res[2] ) << 8 | ord( res[1] );
	}
	ret_arr["data"] = res;
	return ret_arr;
}
func mysql_scramble_password( password, salt ){
	var password, salt;
	var scramble, stage1, stage2, stage3, i;
	scramble = "";
	stage1 = SHA1( password );
	stage2 = SHA1( stage1 );
	stage3 = SHA1( NASLString( salt, stage2 ) );
	for(i = 0;i < strlen( stage3 );i++){
		scramble += raw_string( ord( stage1[i] ) ^ ord( stage3[i] ) );
	}
	return scramble;
}
func mysql_get_salt( data ){
	var data;
	var vers_length, i, salt;
	vers_length = 0;
	for(i = 1;i < strlen( data );i++){
		if(ord( data[i] ) == 0){
			vers_length = i;
			break;
		}
	}
	if(vers_length == 0){
		return FALSE;
	}
	if(strlen( data ) < 43 + vers_length){
		return FALSE;
	}
	salt = substr( data, vers_length + 5, vers_length + 12 );
	if(strlen( data ) > vers_length + 44){
		salt += substr( data, vers_length + 32, vers_length + 43 );
	}
	return salt;
}
func mysql_login( socket, user, password, db ){
	var socket, user, password, db;
	var res, salt, scramble, data;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#mysql_login" );
		exit( 0 );
	}
	res = mysql_recv_server_handshake( socket: socket );
	if(!salt = mysql_get_salt( data: res )){
		return FALSE;
	}
	scramble = mysql_scramble_password( password: password, salt: salt );
	if( db ) {
		data = raw_string( 0x0d, 0xa2 ) + raw_string( 0x2a, 0x00 ) + raw_string( 0xff, 0xff, 0xff, 0x00 ) + raw_string( 0x21 ) + crap( data: raw_string( 0x00 ), length: 23 ) + user + raw_string( 0x00 ) + mkbyte( strlen( scramble ) ) + scramble + db + raw_string( 0x00 ) + "mysql_native_password" + raw_string( 0x00 );
	}
	else {
		data = raw_string( 0x05, 0xa2 ) + raw_string( 0x2a, 0x00 ) + raw_string( 0xff, 0xff, 0xff, 0x00 ) + raw_string( 0x21 ) + crap( data: raw_string( 0x00 ), length: 23 ) + user + raw_string( 0x00 ) + mkbyte( strlen( scramble ) ) + scramble + "mysql_native_password" + raw_string( 0x00 );
	}
	mysql_send_packet( socket: socket, data: data );
	res = mysql_recv_packet( socket: socket );
	if(res["err"]){
		return FALSE;
	}
	return TRUE;
}

