var _string_hex_func_debug;
_string_hex_func_debug = 0;
func hex2raw( s ){
	var s;
	var l, i, j, ret;
	if(isnull( s )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#s#-#hex2raw" );
	}
	s = chomp( s );
	l = strlen( s );
	if(l % 2){
		if(_string_hex_func_debug){
			display( "hex2raw: odd string: ", s, "\\n" );
		}
		l--;
	}
	s = tolower( s );
	for(i = 0;i < l;i += 2){
		if( ord( s[i] ) >= ord( "0" ) && ord( s[i] ) <= ord( "9" ) ) {
			j = int( s[i] );
		}
		else {
			j = int( ( ord( s[i] ) - ord( "a" ) ) + 10 );
		}
		j *= 16;
		if( ord( s[i + 1] ) >= ord( "0" ) && ord( s[i + 1] ) <= ord( "9" ) ) {
			j += int( s[i + 1] );
		}
		else {
			j += int( ( ord( s[i + 1] ) - ord( "a" ) ) + 10 );
		}
		ret += raw_string( j );
	}
	return ret;
}

