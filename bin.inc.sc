var OP_LITTLE_ENDIAN, OP_BIG_ENDIAN, OP_NATIVE_ENDIAN, OP_NETWORK_ENDIAN, OP_DEFAULT_ENDIAN;
OP_LITTLE_ENDIAN = "<";
OP_BIG_ENDIAN = ">";
OP_NATIVE_ENDIAN = "=";
OP_NETWORK_ENDIAN = "!";
OP_DEFAULT_ENDIAN = OP_NATIVE_ENDIAN;
var OP_UINT_8, OP_UINT_16, OP_UINT_32, OP_UINT_64, OP_PAD_BYTE, VAL_PAD_BYTE, OP_STRING, OP_STRING_NULL, OP_STRING_HEX;
OP_UINT_8 = "B";
OP_UINT_16 = "S";
OP_UINT_32 = "L";
OP_UINT_64 = "H";
OP_PAD_BYTE = "x";
VAL_PAD_BYTE = "\0";
OP_STRING = "A";
OP_STRING_NULL = "z";
OP_STRING_HEX = "X";
func bin_pack( format ){
	var args;
	var format_len, endianness, iOp;
	var result, iArg;
	args = _FCT_ANON_ARGS;
	format_len = strlen( format );
	if( format[0] == OP_LITTLE_ENDIAN || format[0] == OP_BIG_ENDIAN || format[0] == OP_NATIVE_ENDIAN || format[0] == OP_NETWORK_ENDIAN ){
		endianness = format[0];
		iOp = 1;
	}
	else {
		endianness = OP_DEFAULT_ENDIAN;
		iOp = 0;
	}
	result = "";
	iArg = 1;
	for(iOp = iOp;iOp < format_len;iOp++){
		if( format[iOp] == OP_UINT_8 ){
			result += pack_uint_8( data: args[iArg] );
			iArg++;
		}
		else {
			if( format[iOp] == OP_UINT_16 ){
				result += pack_uint_16( data: args[iArg], endianness: endianness );
				iArg++;
			}
			else {
				if( format[iOp] == OP_UINT_32 ){
					result += pack_uint_32( data: args[iArg], endianness: endianness );
					iArg++;
				}
				else {
					if( format[iOp] == OP_UINT_64 ){
						result += pack_uint_64( data: args[iArg], endianness: endianness );
						iArg++;
					}
					else {
						if( format[iOp] == OP_PAD_BYTE ){
							result += pack_pad_byte();
						}
						else {
							if( format[iOp] == OP_STRING ){
								result += pack_string( data: args[iArg] );
								iArg++;
							}
							else {
								if( format[iOp] == OP_STRING_NULL ){
									result += pack_string_null( data: args[iArg] );
									iArg++;
								}
								else {
									if( format[iOp] == OP_STRING_HEX ){
										result += pack_string_hex( data: args[iArg] );
										iArg++;
									}
									else {
										if(format[iOp] == OP_LITTLE_ENDIAN || format[iOp] == OP_BIG_ENDIAN || format[iOp] == OP_NATIVE_ENDIAN || format[iOp] == OP_NETWORK_ENDIAN){
											endianness = format[iOp];
											continue;
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return result;
}
func bin_unpack( format, blob, pos ){
	var lens, pos_old;
	var format_len, endianness, iOp;
	var result, iLen, iField, unpack_struct, data;
	if(isnull( pos )){
		pos = 0;
	}
	lens = _FCT_ANON_ARGS;
	if(format){
		lens = lens[1:];
	}
	if(blob){
		lens = lens[1:];
	}
	if(pos){
		lens = lens[1:];
	}
	pos_old = pos;
	format_len = strlen( format );
	if( format[0] == OP_LITTLE_ENDIAN || format[0] == OP_BIG_ENDIAN || format[0] == OP_NATIVE_ENDIAN || format[0] == OP_NETWORK_ENDIAN ){
		endianness = format[0];
		iOp = 1;
	}
	else {
		endianness = OP_DEFAULT_ENDIAN;
		iOp = 0;
	}
	iField = 0;
	iLen = 0;
	for(iOp = iOp;iOp < format_len;iOp++){
		if( format[iOp] == OP_UINT_8 ){
			unpack_struct = unpack_uint_8( blob: blob, pos: pos );
			data[iField] = unpack_struct["data"];
			pos += strlen( unpack_struct["blob"] );
			iField++;
		}
		else {
			if( format[iOp] == OP_UINT_16 ){
				unpack_struct = unpack_uint_16( blob: blob, pos: pos, endianness: endianness );
				data[iField] = unpack_struct["data"];
				pos += strlen( unpack_struct["blob"] );
				iField++;
			}
			else {
				if( format[iOp] == OP_UINT_32 ){
					unpack_struct = unpack_uint_32( blob: blob, pos: pos, endianness: endianness );
					data[iField] = unpack_struct["data"];
					pos += strlen( unpack_struct["blob"] );
					iField++;
				}
				else {
					if( format[iOp] == OP_UINT_64 ){
						unpack_struct = unpack_uint_64( blob: blob, pos: pos, endianness: endianness );
						data[iField] = unpack_struct["data"];
						pos += strlen( unpack_struct["blob"] );
						iField++;
					}
					else {
						if( format[iOp] == OP_PAD_BYTE ){
							pos += unpack_pad_byte( blob: blob, pos: pos );
						}
						else {
							if( format[iOp] == OP_STRING ){
								unpack_struct = unpack_string( blob: blob, pos: pos, len: lens[iLen] );
								data[iField] = unpack_struct["data"];
								pos += strlen( unpack_struct["blob"] );
								iField++;
								iLen++;
							}
							else {
								if( format[iOp] == OP_STRING_NULL ){
									unpack_struct = unpack_string_null( blob: blob, pos: pos );
									data[iField] = unpack_struct["data"];
									pos += strlen( unpack_struct["blob"] );
									iField++;
								}
								else {
									if( format[iOp] == OP_STRING_HEX ){
										unpack_struct = unpack_string_hex( blob: blob, pos: pos, len: lens[iLen] );
										data[iField] = unpack_struct["data"];
										pos += strlen( unpack_struct["blob"] );
										iField++;
										iLen++;
									}
									else {
										if(format[iOp] == OP_LITTLE_ENDIAN || format[iOp] == OP_BIG_ENDIAN || format[iOp] == OP_NATIVE_ENDIAN || format[iOp] == OP_NETWORK_ENDIAN){
											endianness = format[iOp];
											continue;
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	result["blob"] = substr( blob, pos_old, pos - 1 );
	result["data"] = data;
	return result;
}
var ALIGN_PAD_BYTE, ALIGN_LEFT, ALIGN_RIGHT, ALIGN_DEAFULT;
ALIGN_PAD_BYTE = raw_string( 0x00 );
ALIGN_LEFT = "left";
ALIGN_RIGHT = "right";
ALIGN_DEFAULT = ALIGN_RIGHT;
func align( blob, boundary, al ){
	var padding_size, padding, i;
	if(isnull( al )){
		al = ALIGN_DEFAULT;
	}
	padding_size = boundary - ( strlen( blob ) % boundary );
	padding = "";
	for(i = 0;i < padding_size;i++){
		padding += ALIGN_PAD_BYTE;
	}
	if( al == ALIGN_LEFT ){
		return blob + padding;
	}
	else {
		return padding + blob;
	}
}
func populate( arr ){
	var result;
	for(i = 0;i < max_index( arr );i++){
		result[_FCT_ANON_ARGS[i]] = arr[i];
	}
	return result;
}
func dump_arr( arr, title ){
	display( "---[ " + title + " ]---\n" );
	var k, e, _key, elem, keyz, elemz;
	k = 0;
	for _key in keys( arr ) {
		keyz[k++] = _key;
	}
	for(e = 0;e < k;e++){
		display( keyz[e] + ":" + arr[keyz[e]] + "\n" );
	}
	display( "--------------\n" );
}
var NATIVE_BYTE_ORDER;
NATIVE_BYTE_ORDER = OP_BIG_ENDIAN;
func pack_uint_8( data ){
	return raw_string( data % 256 );
}
func unpack_uint_8( blob, pos ){
	var result;
	result["data"] = ord( blob[pos] );
	result["blob"] = substr( blob, pos, pos );
	return result;
}
func pack_uint_16( data, endianness ){
	var uint_16, uint_16_lo, uint_16_hi;
	var result;
	uint_16 = data % ( 256 * 256 );
	uint_16_lo = uint_16 % 256;
	uint_16_hi = uint_16 / 256;
	if(endianness == OP_NATIVE_ENDIAN){
		endianness = NATIVE_BYTE_ORDER;
	}
	if( endianness == OP_LITTLE_ENDIAN ){
		result = raw_string( uint_16_lo, uint_16_hi );
	}
	else {
		if(endianness == OP_BIG_ENDIAN || endianness == OP_NETWORK_ENDIAN){
			result = raw_string( uint_16_hi, uint_16_lo );
		}
	}
	return result;
}
func unpack_uint_16( blob, pos, endianness ){
	var result;
	if(isnull( pos )){
		pos = 0;
	}
	if(endianness == OP_NATIVE_ENDIAN){
		endianness = NATIVE_BYTE_ORDER;
	}
	if( endianness == OP_LITTLE_ENDIAN ){
		result["data"] = ord( blob[pos] ) + ord( blob[pos + 1] ) * 256;
	}
	else {
		if(endianness == OP_BIG_ENDIAN || endianness == OP_NETWORK_ENDIAN){
			result["data"] = ord( blob[pos] ) * 256 + ord( blob[pos + 1] );
		}
	}
	result["blob"] = substr( blob, pos, pos + 1 );
	return result;
}
func pack_uint_32( data, endianness ){
	var uint_32, uint_32_lo, uint_32_hi, uint_32_lo_lo, uint_32_lo_hi, uint_32_hi_lo, uint_32_hi_hi;
	var result;
	uint_32 = data;
	uint_32_lo = uint_32 % ( 256 * 256 );
	uint_32_hi = uint_32 / ( 256 * 256 );
	uint_32_lo_lo = uint_32_lo % 256;
	uint_32_lo_hi = uint_32_lo / 256;
	uint_32_hi_lo = uint_32_hi % 256;
	uint_32_hi_hi = uint_32_hi / 256;
	if(endianness == OP_NATIVE_ENDIAN){
		endianness = NATIVE_BYTE_ORDER;
	}
	if( endianness == OP_LITTLE_ENDIAN ){
		result = raw_string( uint_32_lo_lo, uint_32_lo_hi, uint_32_hi_lo, uint_32_hi_hi );
	}
	else {
		if(endianness == OP_BIG_ENDIAN || endianness == OP_NETWORK_ENDIAN){
			result = raw_string( uint_32_hi_hi, uint_32_hi_lo, uint_32_lo_hi, uint_32_lo_lo );
		}
	}
	return result;
}
func unpack_uint_32( blob, pos, endianness ){
	var result;
	if(isnull( pos )){
		pos = 0;
	}
	if(endianness == OP_NATIVE_ENDIAN){
		endianness = NATIVE_BYTE_ORDER;
	}
	if( endianness == OP_LITTLE_ENDIAN ){
		result["data"] = ord( blob[pos] ) + ord( blob[pos + 1] ) * 256 + ord( blob[pos + 2] ) * 256 * 256 + ord( blob[pos + 3] ) * 256 * 256 * 256;
	}
	else {
		if(endianness == OP_BIG_ENDIAN || endianness == OP_NETWORK_ENDIAN){
			result["data"] = ord( blob[pos + 3] ) + ord( blob[pos + 2] ) * 256 + ord( blob[pos + 1] ) * 256 * 256 + ord( blob[pos] ) * 256 * 256 * 256;
		}
	}
	result["blob"] = substr( blob, pos, pos + 3 );
	return result;
}
func pack_uint_64( data, endianness ){
	var result;
	if(endianness == OP_NATIVE_ENDIAN){
		endianness = NATIVE_BYTE_ORDER;
	}
	if( endianness == OP_LITTLE_ENDIAN ){
		result = pack_uint_32( data: data, endianness: endianness ) + raw_string( 0x00, 0x00, 0x00, 0x00 );
	}
	else {
		if(endianness == OP_BIG_ENDIAN || endianness == OP_NETWORK_ENDIAN){
			result = raw_string( 0x00, 0x00, 0x00, 0x00 ) + pack_uint_32( data: data, endianness: endianness );
		}
	}
	return result;
}
func unpack_uint_64( blob, pos, endianness ){
	var unpack_struct, result;
	if(endianness == OP_NATIVE_ENDIAN){
		endianness = NATIVE_BYTE_ORDER;
	}
	if( endianness == OP_LITTLE_ENDIAN ){
		unpack_struct = unpack_uint_32( blob: blob, endianness: endianness );
		result["data"] = unpack_struct["data"];
	}
	else {
		if(endianness == OP_BIG_ENDIAN || endianness == OP_NETWORK_ENDIAN){
			unpack_struct = unpack_uint_32( blob: blob, pos: pos + 4, endianness: endianness );
			result["data"] = unpack_struct["data"];
		}
	}
	result["blob"] = substr( blob, pos, pos + 7 );
	return result;
}
func pack_pad_byte(  ){
	return VAL_PAD_BYTE;
}
func unpack_pad_byte( blob, pos ){
	return 1;
}
func pack_string( data ){
	return data;
}
func unpack_string( blob, pos, len ){
	var result;
	if(isnull( len )){
		len = strlen( blob ) - pos;
	}
	result["data"] = substr( blob, pos, pos + len - 1 );
	result["blob"] = result["data"];
	return result;
}
func pack_string_null( data ){
	return data + raw_string( 0x00 );
}
func unpack_string_null( blob, pos ){
	var result, i, blob_len;
	result["data"] = "";
	result["blob"] = "";
	blob_len = strlen( blob );
	for(i = pos;i < blob_len;i++){
		result["blob"] += blob[i];
		if(blob[i] == raw_string( 0x00 )){
			break;
		}
		result["data"] += blob[i];
	}
	return result;
}
func pack_string_hex( data ){
	var hex, hex_len, result;
	var val;
	hex = tolower( data );
	hex = ereg_replace( string: hex, pattern: "0x|[' ''\\r''\\n''\\t']", replace: "" );
	hex_len = strlen( hex );
	result = "";
	for(i = 0;i < hex_len;i = i + 2){
		if( ord( hex[i] ) >= ord( "a" ) && ord( hex[i] ) <= ord( "f" ) ){
			val = 16 * ( ord( hex[i] ) - ord( "a" ) + 10 );
		}
		else {
			if( ord( hex[i] ) >= ord( "0" ) && ord( hex[i] ) <= ord( "9" ) ){
				val = 16 * ( ord( hex[i] ) - ord( "0" ) );
			}
			else {
				continue;
			}
		}
		if( ord( hex[i + 1] ) >= ord( "a" ) && ord( hex[i + 1] ) <= ord( "f" ) ){
			val += ( ord( hex[i + 1] ) - ord( "a" ) + 10 );
		}
		else {
			if( ord( hex[i + 1] ) >= ord( "0" ) && ord( hex[i + 1] ) <= ord( "9" ) ){
				val += ord( hex[i + 1] ) - ord( "0" );
				;
			}
			else {
				continue;
			}
		}
		result += raw_string( val );
	}
	return result;
}
func unpack_string_hex( blob, pos, len ){
	var hexstr;
	var result;
	if(isnull( len )){
		len = strlen( blob ) - pos;
	}
	hexstr = "";
	for(i = 0;i < len;i++){
		hexstr += hex( ord( blob[pos + i] ) ) + ",";
	}
	result["data"] = hexstr;
	result["blob"] = substr( blob, pos, pos + len - 1 );
	return result;
}
func reverse_blob( blob ){
	var blob;
	var i, result;
	if(isnull( blob )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#blob#-#reverse_blob" );
		return;
	}
	for(i = 0;i < strlen( blob );i++){
		result = blob[i] + result;
	}
	return result;
}

