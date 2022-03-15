func rand_str( length, charset ){
	var l, i, s, n, length, charset;
	if(!charset){
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
	}
	if(isnull( length )){
		length = 8;
	}
	l = strlen( charset );
	s = "";
	for(i = 0;i < length;i++){
		n = rand() % l;
		s += charset[n];
	}
	return s;
}
func base64_decode( str, key_str ){
	var len, i, j, k, ret, base64, b64, a, b, c, o, str, key_str;
	if(isnull( str )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#str#-#base64_decode" );
	}
	len = strlen( str );
	ret = "";
	if( key_str ) {
		base64 = key_str;
	}
	else {
		base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	}
	for(i = 0;i < 256;i++){
		b64[i] = 0;
	}
	for(i = 0;i < strlen( base64 );i++){
		b64[ord( base64[i] )] = i;
	}
	for(j = 0;j < len;j += 4){
		for(i = 0;i < 4;i++){
			c = ord( str[j + i] );
			a[i] = c;
			b[i] = b64[c];
		}
		o[0] = ( b[0] << 2 ) | ( b[1] >> 4 );
		o[1] = ( b[1] << 4 ) | ( b[2] >> 2 );
		o[2] = ( b[2] << 6 ) | b[3];
		if( a[2] == ord( "=" ) ){
			i = 1;
		}
		else {
			if( a[3] == ord( "=" ) ){
				i = 2;
			}
			else {
				i = 3;
			}
		}
		for(k = 0;k < i;k++){
			ret += raw_string( int( o[k] ) & 255 );
		}
		if(i < 3){
			break;
		}
	}
	return ret;
}
func base64_code( c ){
	var c, __base64_code;
	__base64_code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if(isnull( c )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#c#-#base64_code" );
	}
	return ( __base64_code[c] );
}
func pow2( x ){
	var __ret, x;
	if(isnull( x )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#x#-#pow2" );
	}
	__ret = 1;
	for(;x;){
		__ret = __ret * 2;
		x = x - 1;
	}
	return ( __ret );
}
func base64( str ){
	var len, i, ret, char_count, _bits, val, cnt, mul, str;
	if(isnull( str )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#str#-#base64" );
	}
	len = strlen( str );
	i = 0;
	ret = "";
	char_count = 0;
	_bits = 0;
	for(;i < len;){
		_bits = _bits + ord( str[i] );
		char_count = char_count + 1;
		if( char_count == 3 ){
			val = _bits / 262144;
			ret = NASLString( ret, base64_code( c: val ) );
			val = _bits / 4096;
			val = val & 0x3F;
			ret = NASLString( ret, base64_code( c: val ) );
			val = _bits / 64;
			val = val & 0x3F;
			ret = NASLString( ret, base64_code( c: val ) );
			val = _bits & 0x3F;
			ret = NASLString( ret, base64_code( c: val ) );
			char_count = 0;
			_bits = 0;
		}
		else {
			_bits = _bits * 256;
		}
		i = i + 1;
	}
	if(!( char_count == 0 )){
		cnt = char_count * 8;
		mul = 16;
		mul = mul - cnt;
		mul = pow2( x: mul );
		_bits = _bits * mul;
		val = _bits / 262144;
		ret = NASLString( ret, base64_code( c: val ) );
		val = _bits / 4096;
		val = val & 0x3F;
		ret = NASLString( ret, base64_code( c: val ) );
		if( char_count == 1 ){
			ret = NASLString( ret, "==" );
		}
		else {
			val = _bits / 64;
			val = val & 0x3F;
			ret = NASLString( ret, base64_code( c: val ), "=" );
		}
	}
	return ( ret );
}
func dec2hex( num ){
	var digits, hex, rem, num;
	if(isnull( num )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#num#-#dec2hex" );
	}
	hex = "";
	num = int( num );
	for(;num > 0;){
		rem = num % 256;
		hex = raw_string( rem, hex );
		num = num / 256;
		if(num > 0 && num < 255){
			hex = raw_string( num, hex );
			num = 0;
		}
	}
	if(!hex){
		hex = raw_string( 0x00 );
	}
	return hex;
}
func cvsdate2unixtime( date ){
	var v, u, date;
	if(!date){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#date#-#cvsdate2unixtime" );
	}
	v = eregmatch( string: date, pattern: ".Date: ([0-9]+)/([01][0-9])/([0-3][0-9]) ([0-2][0-9]):([0-6][0-9]):([0-6][0-9]) \\$" );
	if(isnull( v )){
		return;
	}
	u = mktime( year: v[1], mon: v[2], mday: v[3], hour: v[3], min: v[5], sec: v[6] );
	return u;
}
func hex2str(  ){
	var xlat, hs, s, i, j;
	hs = _FCT_ANON_ARGS[0];
	if(isnull( hs )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#hex2str" );
		return;
	}
	s = "";
	for(i = 0;i < 256;++i){
		xlat[tolower( substr( hex( i ), 2 ) )] = raw_string( i );
	}
	for(j = 0;j < strlen( hs ) / 2;++j){
		s += xlat[tolower( substr( hs, 2 * j, 2 * j + 1 ) )];
	}
	return s;
}
func is_printer_mac( mac ){
	var mac, mac_s, p_vendors, max_prefix, mac_vendor, _pv;
	if(!mac){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#mac#-#is_printer_mac" );
		return;
	}
	mac_s = split( buffer: mac, sep: ":", keep: FALSE );
	if(max_index( mac_s ) != 6){
		return;
	}
	p_vendors = make_list( "xerox",
		 "canon",
		 "kyocera",
		 "lexmark",
		 "hewlettp",
		 "samsung" );
	mac_prefix = toupper( mac_s[0] + ":" + mac_s[1] + ":" + mac_s[2] );
	mac_vendor = tolower( mac_prefixes[mac_prefix] );
	if(!mac_vendor){
		return;
	}
	for _pv in p_vendors {
		if(mac_vendor == _pv){
			return TRUE;
		}
	}
	return;
}
func bin2string( ddata, noprint_replacement ){
	var ddata, noprint_replacement;
	var tmp, i, j, linenumber, len, data, c;
	if(isnull( ddata )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#ddata#-#bin2string" );
		return NULL;
	}
	len = strlen( ddata );
	linenumber = len / 16;
	for(i = 0;i <= linenumber;i++){
		data = "";
		for(j = 0;j < 16;j++){
			if(( i * 16 + j ) < len){
				c = ddata[i * 16 + j];
				if( isprint( c: c ) ){
					data += c;
				}
				else {
					if(!isnull( noprint_replacement )){
						data += noprint_replacement;
					}
				}
			}
		}
		tmp += NASLString( data );
	}
	return tmp;
}
func ascii2unicode( data ){
	var data, len, ret, i;
	if(isnull( data )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#ascii2unicode" );
		return;
	}
	len = strlen( data );
	for(i = 0;i < len;i++){
		ret += data[i] + raw_string( 0x00 );
	}
	return ret;
}
func text_format_table( array, sep, columnheader, maxentries ){
	var array, sep, columnheader, maxentries;
	var currententries, _key, len, maxlen, hascolumnheader, columnheaderlen, fulllen, seplen, value, flen, paddinglen, report, reportheader, reportheaderlen;
	if(!array){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#array#-#text_format_table" );
		return;
	}
	if(!is_array( array )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#text_format_table: No array passed in 'array' parameter" );
		return;
	}
	if(isnull( sep )){
		sep = " : ";
	}
	currententries = 0;
	for _key in sort( keys( array ) ) {
		currententries++;
		if(maxentries > 0 && currententries > maxentries){
			break;
		}
		_key = chomp( _key );
		_key = ereg_replace( string: _key, pattern: "[\r\n]+", replace: "<newline>" );
		len = strlen( _key );
		if(!maxlen){
			maxlen = len;
			continue;
		}
		if(maxlen < len){
			maxlen = len;
		}
	}
	if(columnheader && is_array( columnheader )){
		hascolumnheader = TRUE;
		columnheaderlen = strlen( chomp( columnheader[0] ) );
		if(maxlen < columnheaderlen){
			maxlen = columnheaderlen;
		}
	}
	currententries = 0;
	fulllen = 0;
	seplen = strlen( sep );
	for _key in sort( keys( array ) ) {
		currententries++;
		if(maxentries > 0 && currententries > maxentries){
			break;
		}
		value = array[_key];
		_key = chomp( _key );
		_key = ereg_replace( string: _key, pattern: "[\r\n]+", replace: "<newline>" );
		flen = strlen( _key );
		paddinglen = ( maxlen - flen );
		value = chomp( value );
		value = ereg_replace( string: value, pattern: "[\r\n]+", replace: "<newline>" );
		valuelen = strlen( value );
		report += _key + crap( data: " ", length: paddinglen ) + sep + value + "\n";
		if(valuelen + maxlen > fulllen){
			fulllen = maxlen + valuelen;
		}
	}
	if(strlen( report )){
		if(hascolumnheader){
			reportheader = chomp( columnheader[0] ) + crap( data: " ", length: maxlen - columnheaderlen ) + sep + chomp( columnheader[1] ) + "\n";
			reportheaderlen = strlen( reportheader ) - 1;
			if( fulllen + seplen < reportheaderlen ) {
				fulllen = reportheaderlen;
			}
			else {
				fulllen += seplen;
			}
			reportheader += crap( data: "-", length: fulllen ) + "\n";
			report = reportheader + report;
		}
		return chomp( report );
	}
}
func eol_date_reached( eol_date ){
	var eol_date, local_time;
	if(!eol_date){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#eol_date#-#eol_date_reached" );
		return;
	}
	if(eol_date == "unknown"){
		return TRUE;
	}
	eol_date = str_replace( string: eol_date, find: "-", keep: FALSE );
	local_time = make_date_str( date: localtime( unixtime() ) );
	if(int( local_time ) >= int( eol_date )){
		return TRUE;
	}
	return;
}
func build_eol_message( eol_type, name, cpe, version, location, skip_version, eol_version, eol_date, eol_url ){
	var eol_type, name, cpe, version, location, skip_version, eol_version, eol_date, eol_url;
	var report;
	if(eol_type != "prod" && eol_type != "os"){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#build_prod_eol_message: Wrong value passed to eol_type. Valid values are: prod, os" );
		return "";
	}
	if( eol_type == "prod" ){
		if(!name){
			set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#name#-#build_eol_message" );
		}
		if(!cpe){
			set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#build_eol_message" );
		}
		if(!version && !skip_version){
			set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version#-#build_eol_message" );
		}
		if(!eol_version && !skip_version){
			set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#eol_version#-#build_eol_message" );
		}
		if(!eol_date){
			set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#eol_date#-#build_eol_message" );
		}
		if( !skip_version ){
			report = "The \"" + name + "\" version on the remote host has reached the end of life.\n\n" + "CPE:               " + cpe + ":" + version + "\n" + "Installed version: " + version;
		}
		else {
			report = "The \"" + name + "\" product on the remote host has reached the end of life.\n\n" + "CPE:               " + cpe;
		}
		if(location){
			report += "\nLocation/URL:      " + location;
		}
		if(eol_version){
			report += "\nEOL version:       " + eol_version;
		}
		if(eol_date){
			report += "\nEOL date:          " + eol_date;
		}
		if(eol_url){
			report += "\nEOL info:          " + eol_url;
		}
	}
	else {
		if(eol_type == "os"){
			if(!name){
				set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#name#-#build_eol_message" );
			}
			if(!cpe){
				set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#build_eol_message" );
			}
			if(!eol_date){
				set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#eol_date#-#build_eol_message" );
			}
			if(!eol_url){
				set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#eol_url#-#build_eol_message" );
			}
			report = "The \"" + name + "\" Operating System on the remote host has reached the end of life.\n\n" + "CPE:               " + cpe;
			if(version && version != "unknown"){
				report += "\nInstalled version,\n";
				report += "build or SP:       " + version;
			}
			if(eol_version){
				report += "\nEOL version:       " + eol_version;
			}
			if(eol_date){
				report += "\nEOL date:          " + eol_date;
			}
			if(eol_url){
				report += "\nEOL info:          " + eol_url;
			}
		}
	}
	return report;
}
func make_date_str( date ){
	var date, time, month, day;
	if(isnull( date )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#date#-#make_date_str" );
		return;
	}
	time = localtime( date );
	month = fancy_date( datestr: time["mon"] );
	day = fancy_date( datestr: time["mday"] );
	return NASLString( time["year"], month, day );
}
func fancy_date( datestr ){
	var datestr;
	if(isnull( datestr )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#datestr#-#fancy_date" );
		return;
	}
	if( int( datestr ) < 10 ) {
		return NASLString( "0", datestr );
	}
	else {
		return datestr;
	}
}
func exploit_commands(  ){
	var res;
	if( _FCT_ANON_ARGS[0] ){
		if( tolower( _FCT_ANON_ARGS[0] ) == "windows" ){
			res = "yes";
		}
		else {
			if(tolower( _FCT_ANON_ARGS[0] ) == "linux"){
				res = "no";
			}
		}
	}
	else {
		res = os_host_runs( "windows" );
	}
	if( res == "yes" ){
		return make_array( "Windows.IP..onfiguration", "ipconfig" );
	}
	else {
		if(res == "no"){
			return make_array( "uid=[0-9]+.*gid=[0-9]+", "id" );
		}
	}
	return make_array( "uid=[0-9]+.*gid=[0-9]+", "id", "Windows.IP..onfiguration", "ipconfig" );
}
func traversal_files(  ){
	var res;
	if( _FCT_ANON_ARGS[0] ){
		if( tolower( _FCT_ANON_ARGS[0] ) == "windows" ){
			res = "yes";
		}
		else {
			if(tolower( _FCT_ANON_ARGS[0] ) == "linux"){
				res = "no";
			}
		}
	}
	else {
		res = os_host_runs( "windows" );
	}
	if( res == "yes" ){
		return make_array( "\\[boot loader\\]", "boot.ini", "; for 16-bit app supporT", "winnt/win.ini", "; for 16-bit app support", "windows/win.ini" );
	}
	else {
		if(res == "no"){
			return make_array( "(root|admin|nobody):[^:]*:[0-9]+:(-2|[0-9]+):([^:]*:){2}", "etc/passwd" );
		}
	}
	return make_array( "(root|admin|nobody):[^:]*:[0-9]+:(-2|[0-9]+):([^:]*:){2}", "etc/passwd", "\\[boot loader\\]", "boot.ini", "; for 16-bit app supporT", "winnt/win.ini", "; for 16-bit app support", "windows/win.ini" );
}
func traversal_pattern( extra_pattern_list, depth ){
	var extra_pattern_list, depth;
	var rounded_up_depth, traversal_pattern;
	if(!depth){
		depth = 6;
	}else{
		depth = int(depth);
	}
	rounded_up_depth = depth;
	if(rounded_up_depth % 2){
		rounded_up_depth++;
	}
	traversal_pattern = make_list( "/",
		 "//",
		 "///",
		 crap( data: "../",
		 length: 3 * depth ),
		 crap( data: ".../",
		 length: 4 * depth ),
		 crap( data: "....//",
		 length: 6 * depth ),
		 crap( data: ".....//",
		 length: 7 * depth ),
		 crap( data: "%20../",
		 length: 6 * depth ),
		 crap( data: "%u0020../",
		 length: 9 * depth ),
		 crap( data: "%20.../",
		 length: 7 * depth ),
		 crap( data: "%u0020.../",
		 length: 10 * depth ),
		 crap( data: "%2e%2e%2f",
		 length: 9 * depth ),
		 crap( data: "%u002e%u002e%u002f",
		 length: 18 * depth ),
		 crap( data: "%2e%2e/",
		 length: 7 * depth ),
		 crap( data: "%u002e%u002e/",
		 length: 13 * depth ),
		 crap( data: "%2e./.%2e/",
		 length: 10 * depth ),
		 crap( data: "%u002e./.%u002e/",
		 length: 16 * depth ),
		 crap( data: "..%2f",
		 length: 5 * depth ),
		 crap( data: "..%u002f",
		 length: 8 * depth ),
		 crap( data: "..%255f",
		 length: 7 * depth ),
		 crap( data: "%252e%252e%255f",
		 length: 15 * depth ),
		 crap( data: ".%252e/",
		 length: 7 * depth ),
		 crap( data: "%c0%ae%c0%ae/",
		 length: 13 * depth ),
		 crap( data: "..///////..////..//////",
		 length: 23 * ( rounded_up_depth / 2 ) ),
		 crap( data: "/%5C..",
		 length: 6 * depth ),
		 ".%2e/" + crap( data: "%2e%2e/",
		 length: 7 * depth ),
		 crap( data: ".%00.../",
		 length: 8 * depth ),
		 crap( data: "../",
		 length: 3 * ( rounded_up_depth / 2 ) ) + "a/" + crap( data: "../",
		 length: 3 * ( rounded_up_depth / 2 ) ),
		 "\\",
		 "\\\\",
		 "\\\\\\",
		 crap( data: "..\\",
		 length: 3 * depth ),
		 crap( data: "...\\",
		 length: 4 * depth ),
		 crap( data: "....\\\\",
		 length: 6 * depth ),
		 crap( data: ".....\\\\",
		 length: 7 * depth ),
		 crap( data: "%20..\\",
		 length: 6 * depth ),
		 crap( data: "%u0020..\\",
		 length: 9 * depth ),
		 crap( data: "%20...\\",
		 length: 7 * depth ),
		 crap( data: "%u0020...\\",
		 length: 10 * depth ),
		 crap( data: "%2e%2e%5c",
		 length: 9 * depth ),
		 crap( data: "%u002e%u002e%u005c",
		 length: 18 * depth ),
		 crap( data: "%2e%2e\\",
		 length: 7 * depth ),
		 crap( data: "%u002e%u002e\\",
		 length: 13 * depth ),
		 crap( data: "%2e.\\.%2e\\",
		 length: 10 * depth ),
		 crap( data: "%u002e.\\.%u002e\\",
		 length: 16 * depth ),
		 crap( data: "..%5c",
		 length: 5 * depth ),
		 crap( data: "..%u005c",
		 length: 8 * depth ),
		 crap( data: "..%255c",
		 length: 7 * depth ),
		 crap( data: "%252e%252e%255c",
		 length: 15 * depth ),
		 crap( data: ".%252e\\",
		 length: 7 * depth ),
		 crap( data: "%c0%ae%c0%ae\\",
		 length: 13 * depth ),
		 crap( data: "..\\\\\\\\\\\\\\..\\\\\\\\..\\\\\\\\\\\\",
		 length: 23 * ( rounded_up_depth / 2 ) ),
		 ".%2e\\" + crap( data: "%2e%2e\\",
		 length: 7 * depth ),
		 crap( data: ".%00...\\",
		 length: 8 * depth ),
		 crap( data: "..\\",
		 length: 3 * ( rounded_up_depth / 2 ) ) + "a\\" + crap( data: "..\\",
		 length: 3 * ( rounded_up_depth / 2 ) ) );
	if( extra_pattern_list && !is_array( extra_pattern_list ) ){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#traversal_pattern(): No list passed in 'extra_pattern_list' parameter" );
	}
	else {
		traversal_pattern = nasl_make_list_unique( traversal_pattern, extra_pattern_list );
	}
	return traversal_pattern;
}
func create_hostname_parts_list(  ){
	var list, hnlist, hn, hnp, hnl, p, parts, i;
	list = make_list();
	if( defined_func( "get_host_names" ) ) {
		hnlist = get_host_names();
	}
	else {
		hnlist = make_list( get_host_name() );
	}
	for hn in hnlist {
		if(!ContainsString( hn, ":" ) && !ereg( string: hn, pattern: "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$" )){
			hnp = split( buffer: hn, sep: ".", keep: FALSE );
			hnl = max_index( hnp );
			parts = "";
			for(i = 0;i < hnl;i++){
				list = make_list( list,
					 hnp[i] );
				parts += "." + hnp[i];
				parts = ereg_replace( pattern: "^\\.", string: parts, replace: "" );
				if(!in_array( search: parts, array: list )){
					list = make_list( list,
						 parts );
				}
			}
			parts = "";
			for(i = 1;i < hnl;i++){
				parts += "." + hnp[i];
				parts = ereg_replace( pattern: "^\\.", string: parts, replace: "" );
				if(!in_array( search: parts, array: list )){
					list = make_list( list,
						 parts );
				}
			}
			parts = "";
			for(i = hnl - 1;i >= 0;i--){
				parts += "." + hnp[i];
				parts = ereg_replace( pattern: "^\\.", string: parts, replace: "" );
				if(!in_array( search: parts, array: list )){
					list = make_list( list,
						 parts );
				}
			}
		}
	}
	return list;
}
func executed_on_gos(  ){
	if(!defined_func( "vendor_version" )){
		return NULL;
	}
	if( IsMatchRegexp( vendor_version(), "^Greenbone OS" ) ){
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func get_local_gos_version(  ){
	var result;
	if( isnull( executed_on_gos() ) ){
		return NULL;
	}
	else {
		if( !executed_on_gos() ){
			return FALSE;
		}
		else {
			result = eregmatch( pattern: "([0-9.]+)$", string: vendor_version() );
			return result[1];
		}
	}
}
func get_vt_strings(  ){
	var ret_array, vt_string, vt_string_dash, vt_string_lo, vt_string_up, rand_numbers, version;
	ret_array = make_array();
	if( executed_on_gos() ){
		vt_string = "GBNVT";
		vt_string_dash = "GBN-VT";
	}
	else {
		vt_string = "OpenVASVT";
		vt_string_dash = "OpenVAS-VT";
	}
	if( OPENVAS_VERSION ) {
		version = OPENVAS_VERSION;
	}
	else {
		version = "1.0";
	}
	vt_string_lo = tolower( vt_string );
	vt_string_up = toupper( vt_string );
	vt_string_dash_lo = tolower( vt_string_dash );
	vt_string_dash_up = toupper( vt_string_dash );
	rand_numbers = NASLString( rand() );
	ret_array["default"] = vt_string;
	ret_array["default_rand"] = vt_string + rand_numbers;
	ret_array["default_hex"] = hexstr( vt_string );
	ret_array["default_rand_hex"] = hexstr( vt_string + rand_numbers );
	ret_array["default_ver_space"] = vt_string + " " + version;
	ret_array["default_ver_dash"] = vt_string + "-" + version;
	ret_array["default_dash"] = vt_string_dash;
	ret_array["default_rand_dash"] = vt_string_dash + rand_numbers;
	ret_array["ping_string"] = "_" + vt_string + substr( rand_numbers, 0, 16 - strlen( vt_string ) - 3 ) + "_";
	ret_array["lowercase"] = vt_string_lo;
	ret_array["lowercase_rand"] = vt_string_lo + rand_numbers;
	ret_array["lowercase_hex"] = hexstr( vt_string_lo );
	ret_array["lowercase_rand_hex"] = hexstr( vt_string_lo + rand_numbers );
	ret_array["lowercase_ver_space"] = vt_string_lo + " " + version;
	ret_array["lowercase_ver_dash"] = vt_string_lo + "-" + version;
	ret_array["lowercase_dash"] = vt_string_dash_lo;
	ret_array["lowercase_rand_dash"] = vt_string_dash_lo + rand_numbers;
	ret_array["uppercase"] = vt_string_up;
	ret_array["uppercase_rand"] = vt_string_up + rand_numbers;
	ret_array["uppercase_hex"] = hexstr( vt_string_up );
	ret_array["uppercase_rand_hex"] = hexstr( vt_string_up + rand_numbers );
	ret_array["uppercase_ver_space"] = vt_string_up + " " + version;
	ret_array["uppercase_ver_dash"] = vt_string_up + "-" + version;
	ret_array["uppercase_dash"] = vt_string_dash_up;
	ret_array["uppercase_rand_dash"] = vt_string_dash_up + rand_numbers;
	return ret_array;
}

