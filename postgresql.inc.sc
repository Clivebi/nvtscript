func postgresql_login( socket, user, password, db ){
	var socket, user, password, db;
	var req, res, x, len, typ, salt, userpass, pass, passlen, code;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#postgresql_login" );
		return NULL;
	}
	if(isnull( user )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#user#-#postgresql_login" );
	}
	if(isnull( password )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#password#-#postgresql_login" );
	}
	req = postgresql_create_startup_packet( user: user, db: db );
	send( socket: socket, data: req );
	res = recv( socket: socket, length: 1 );
	if(isnull( res ) || res[0] != "R"){
		return FALSE;
	}
	res += recv( socket: socket, length: 4 );
	if(strlen( res ) < 5){
		return FALSE;
	}
	x = substr( res, 1, 4 );
	len = ord( x[0] ) << 24 | ord( x[1] ) << 16 | ord( x[2] ) << 8 | ord( x[3] );
	res += recv( socket: socket, length: len );
	if(strlen( res ) < len || strlen( res ) < 8){
		return FALSE;
	}
	typ = substr( res, strlen( res ) - 6, strlen( res ) - 5 );
	typ = ord( typ[1] );
	if(typ == 0){
		return TRUE;
	}
	if(typ != 5){
		return FALSE;
	}
	salt = substr( res, strlen( res ) - 4 );
	userpass = hexstr( MD5( password + user ) );
	pass = "md5" + hexstr( MD5( userpass + salt ) );
	passlen = strlen( pass ) + 5;
	req = NASLString( raw_string( 0x70 ), raw_string( ( passlen >> 24 ) & 0xff, ( passlen >> 16 ) & 0xff, ( passlen >> 8 ) & 0xff, ( passlen ) & 0xff ), pass, raw_string( 0 ) );
	send( socket: socket, data: req );
	res = recv( socket: socket, length: 1 );
	if(isnull( res ) || res[0] != "R"){
		return FALSE;
	}
	res += recv( socket: socket, length: 8 );
	if(strlen( res ) < 8){
		return FALSE;
	}
	code = substr( res, 5, strlen( res ) );
	if( res[0] == "R" && hexstr( code ) == "00000000" ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func postgresql_create_startup_packet( user, db ){
	var user, db;
	var req, h, null, len;
	if(isnull( user )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#user#-#postgresql_create_startup_packet" );
	}
	h = raw_string( ( 0x03 >> 8 ) & 0xFF, 0x03 & 0xFF, ( 0x00 >> 8 ) & 0xFF, 0x00 & 0xFF );
	null = raw_string( 0 );
	if(isnull( db )){
		db = "postgres";
	}
	req = NASLString( h, "user", null, user, null, "database", null, db, null, "client_encoding", null, "UNICODE", null, "DateStyle", null, "ISO", null, null );
	len = strlen( req ) + 4;
	req = raw_string( ( len >> 24 ) & 0xff, ( len >> 16 ) & 0xff, ( len >> 8 ) & 0xff, ( len ) & 0xff ) + req;
	return req;
}

