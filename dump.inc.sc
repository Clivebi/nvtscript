func line2string( line, linenumber ){
	var tmp, pos, line, linenumber;
	if(isnull( line )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#line#-#line2string" );
	}
	line = line * 16;
	tmp = raw_string( ( line >> 24 ) & 0xFF, ( line >> 16 ) & 0xFF, ( line >> 8 ) & 0xFF, ( line ) & 0xFF );
	if( linenumber < 256 ){
		pos = 3;
	}
	else {
		if( linenumber < 65536 ){
			pos = 2;
		}
		else {
			if( linenumber < 16777216 ){
				pos = 1;
			}
			else {
				pos = 0;
			}
		}
	}
	return NASLString( "0x", toupper( hexstr( substr( tmp, pos, 3 ) ) ), ": " );
}
func isprint( c ){
	var c;
	if(isnull( c )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#c#-#isprint" );
		return NULL;
	}
	if( ( ord( c ) >= 0x20 ) && ( ord( c ) <= 0x7E ) ){
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func hexdump( ddata ){
	var tmp, i, j, line, linenumber, len, data, c, ddata;
	if(isnull( ddata )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#ddata#-#hexdump" );
	}
	len = strlen( ddata );
	linenumber = len / 16;
	for(i = 0;i <= linenumber;i++){
		line = line2string( line: i, linenumber: len );
		data = "";
		for(j = 0;j < 16;j++){
			if( ( i * 16 + j ) < len ){
				line += NASLString( " ", toupper( hexstr( ddata[i * 16 + j] ) ) );
				c = ddata[i * 16 + j];
				if( isprint( c: c ) ){
					data += c;
				}
				else {
					data += ".";
				}
			}
			else {
				line += "   ";
				data += " ";
			}
		}
		tmp += NASLString( line, "    ", data, "\\n" );
	}
	return tmp;
}
func dump( dtitle, ddata ){
	var dtitle, ddata;
	if(isnull( ddata )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#ddata#-#dump" );
	}
	if(!isnull( dtitle )){
		display( "---[ " + dtitle + " ]---\n" );
	}
	display( hexdump( ddata: ddata ) );
}

