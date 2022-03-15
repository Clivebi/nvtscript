func rsync_connect( port ){
	var port;
	var soc, banner, buf;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#rsync_connect" );
		return FALSE;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		return NULL;
	}
	banner = recv_line( socket: soc, length: 8096 );
	if(isnull( banner )){
		close( soc );
		return FALSE;
	}
	send( socket: soc, data: "@RSYNCD: 29.0\n" );
	for(;TRUE;){
		buf = recv_line( socket: soc, length: 8096 );
		if(!buf || strstr( buf, "@ERROR" )){
			break;
		}
	}
	return soc;
}
func rsync_get_module_list( soc ){
	var soc;
	var num, line, ret;
	if(!soc){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#soc#-#rsync_get_module_list" );
		return FALSE;
	}
	num = 0;
	send( socket: soc, data: "#list\r\n" );
	for(;TRUE;){
		line = recv_line( socket: soc, length: 8096, timeout: 1 );
		if(!line || strstr( line, "@RSYNCD" )){
			break;
		}
		ret[num++] = line;
	}
	return ret;
}
func rsync_authentication_required( module, port ){
	var module, port;
	var soc, line;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#rsync_authentication_required" );
		return FALSE;
	}
	soc = rsync_connect( port: port );
	if(!soc){
		return "unknown";
	}
	send( socket: soc, data: NASLString( module + "\r\n" ) );
	line = recv_line( socket: soc, length: 8096 );
	close( soc );
	if( strstr( line, "@RSYNCD: OK" ) ){
		return "no";
	}
	else {
		if( strstr( line, "@RSYNCD: AUTHREQD" ) ){
			return "yes";
		}
		else {
			return "unknown";
		}
	}
}
func rsync_get_file( soc, module, file ){
	var soc, module, file;
	var buf, s, b, ret, plen, pfile, flen, file_end;
	if(isnull( soc )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#soc#-#rsync_get_file" );
		return FALSE;
	}
	if(isnull( module )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#module#-#rsync_get_file" );
		return FALSE;
	}
	if(isnull( file )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#file#-#rsync_get_file" );
		return FALSE;
	}
	set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
	send( socket: soc, data: module + "\n" );
	buf = recv_line( socket: soc, length: 4096 );
	if(!ContainsString( buf, "@RSYNCD: OK" )){
		return FALSE;
	}
	send( socket: soc, data: "--server\n--sender\n-L\n.\n" + module + "/" + file + "\n\n" );
	buf = recv( socket: soc, length: 4096 );
	send( socket: soc, data: raw_string( 0, 0, 0, 0 ) );
	buf = recv( socket: soc, length: 4096 );
	if(!buf || buf == ""){
		return FALSE;
	}
	s = hex2raw( s: "0000000000a000000000000000000000000000000000" );
	send( socket: soc, data: s );
	for(;b = recv( socket: soc, length: 1024 );){
		ret += b;
	}
	plen = strlen( s ) + 4;
	pfile = strlen( s ) + 8;
	if(isnull( ret ) || strlen( ret ) < ( pfile + 4 )){
		return FALSE;
	}
	flen = getdword( blob: ret, pos: plen );
	file_end = pfile + ( flen - 1 );
	if(strlen( ret ) < file_end){
		return FALSE;
	}
	return substr( ret, pfile, file_end );
}
func rsync_get_port( default ){
	var default;
	var port;
	if(!default){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#rsync_get_port" );
	}
	port = get_kb_item( "Services/rsync" );
	if(port){
		default = port;
	}
	if(port_is_marked_fragile( port: default )){
		exit( 0 );
	}
	if(!get_port_state( default )){
		exit( 0 );
	}
	return default;
}

