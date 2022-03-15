var BYTE_ORDER;
BYTE_ORDER_LITTLE_ENDIAN = 1;
BYTE_ORDER_BIG_ENDIAN = 2;
BYTE_ORDER = BYTE_ORDER_BIG_ENDIAN;
func mkbyte(  ){
	var value, byte;
	value = _FCT_ANON_ARGS[0];
	if(isnull( value )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#mkbyte" );
	}
	byte = raw_string( 0xFF & value );
	return byte;
}
func mkword(  ){
	var value, DATA;
	value = _FCT_ANON_ARGS[0];
	if(isnull( value )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#mkword" );
		return 0;
	}
	if( BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN ){
		DATA = raw_string( ( value >> 8 ) & 255, value & 255 );
	}
	else {
		DATA = raw_string( value & 255, ( value >> 8 ) & 255 );
	}
	return DATA;
}
func set_byte_order(  ){
	var arg;
	arg = _FCT_ANON_ARGS[0];
	if( !isnull( arg ) ){
		if(arg == BYTE_ORDER_BIG_ENDIAN || arg == BYTE_ORDER_LITTLE_ENDIAN){
			BYTE_ORDER = arg;
		}
	}
	else {
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#set_byte_order" );
	}
}
func mkdword(  ){
	var value, DATA;
	value = _FCT_ANON_ARGS[0];
	if(isnull( value )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#mkdword" );
		return 0;
	}
	if( BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN ){
		DATA = raw_string( ( value >> 24 ) & 255, ( value >> 16 ) & 255, ( value >> 8 ) & 255, ( value ) & 255 );
	}
	else {
		DATA = raw_string( value & 255, ( value >> 8 ) & 255, ( value >> 16 ) & 255, ( value >> 24 ) & 255 );
	}
	return DATA;
}
func mkpad(  ){
	var length, DATA, arg;
	arg = _FCT_ANON_ARGS[0];
	if( isnull( arg ) ){
		length = 1000;
	}
	else {
		length = arg;
	}
	DATA = crap( data: raw_string( 0x00 ), length: length );
	return DATA;
}
func getword( blob, pos ){
	var DATA, blob, pos;
	if(isnull( blob )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#blob#-#getword" );
	}
	if(!pos){
		pos = 0;
	}
	if(!blob = substr( blob, pos )){
		return 0;
	}
	if( BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN ){
		DATA = ord( blob[0] ) << 8 | ord( blob[1] );
	}
	else {
		DATA = ord( blob[0] ) | ord( blob[1] ) << 8;
	}
	return DATA;
}
func getdword( blob, pos ){
	var DATA, blob, pos;
	if(isnull( blob )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#blob#-#getdword" );
	}
	if(!pos){
		pos = 0;
	}
	if(!blob = substr( blob, pos )){
		return 0;
	}
	if( BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN ){
		DATA = ord( blob[0] ) << 24 | ord( blob[1] ) << 16 | ord( blob[2] ) << 8 | ord( blob[3] );
	}
	else {
		DATA = ord( blob[0] ) | ord( blob[1] ) << 8 | ord( blob[2] ) << 16 | ord( blob[3] ) << 24;
	}
	return DATA;
}
func dec2bin( dec ){
	var dnum, res, dec;
	if(isnull( dec )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dec#-#dec2bin" );
	}
	dnum = int( dec );
	if(dnum == 0){
		return dnum;
	}
	for(;dnum > 0;){
		res = NASLString( dnum & 1 ) + res;
		dnum = dnum >>= 1;
	}
	for(;strlen( res ) < 8;){
		res = NASLString( 0 ) + res;
	}
	return res;
}
func bin2dec( bin ){
	var res, bin, d, c;
	if(isnull( bin )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#bin#-#bin2dec" );
	}
	bin = NASLString( bin );
	if(bin == "0"){
		return 0;
	}
	d = 0;
	for(c = strlen( bin ) - 1;c >= 0;c--){
		if(bin[c] != "0" && bin[c] != "1"){
			return -1;
		}
		res += int( bin[c] ) * ( power(2,d) );
		d++;
	}
	return res;
}
func raw_int32( i ){
	var i;
	var buf;
	buf = raw_string( ( i >> 24 ) & 255, ( i >> 16 ) & 255, ( i >> 8 ) & 255, ( i ) & 255 );
	return buf;
}
func raw_int8( i ){
	var i;
	var buf;
	buf = raw_string( ( i ) & 255 );
	return buf;
}
func ntol( buffer, begin ){
	var buffer, begin;
	var len;
	len = 16777216 * ord( buffer[begin] ) + ord( buffer[begin + 1] ) * 65536 + ord( buffer[begin + 2] ) * 256 + ord( buffer[begin + 3] );
	return len;
}

