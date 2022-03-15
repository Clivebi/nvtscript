func smb_get_fileversion_from_cache( file_name ){
	var file_name;
	var infos, ret_array;
	if(!file_name){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#file_name#-#smb_get_fileversion_from_cache" );
		return;
	}
	if(file_name != "edgehtml.dll" && file_name != "mshtml.dll"){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#smb_get_fileversion_from_cache: Unsupported file name '" + file_name + "' passed. Currently supported: edgehtml.dll or mshtml.dll." );
		return;
	}
	infos = get_kb_item( "SMB/lsc_file_version_cache/" + file_name + "/infos" );
	if(!infos){
		return FALSE;
	}
	info_list = split( buffer: infos, sep: "#--#", keep: FALSE );
	if(max_index( info_list ) != 2){
		return FALSE;
	}
	ret_arr["path"] = info_list[0];
	ret_arr["version"] = info_list[1];
	return ret_arr;
}
func GetVersion( socket, uid, tid, fid, offset, verstr, debug ){
	var socket, uid, tid, fid, offset, verstr, debug;
	var pattern, patlen, fsize, offset, start, chunk, i, tmp;
	var data, version, len, ver_len, vers, _item, retVal, ver;
	if(isnull( socket )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#GetVersion" );
	}
	if(isnull( uid )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#uid#-#GetVersion" );
	}
	if(isnull( tid )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#tid#-#GetVersion" );
	}
	if(isnull( fid )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#fid#-#GetVersion" );
	}
	pattern = "F?i?l?e?V?e?r?s?i?o?n";
	if( verstr == "prod" ){
		pattern = "P?r?o?d?u?c?t?V?e?r?s?i?o?n";
	}
	else {
		if(verstr){
			pattern = verstr;
		}
	}
	patlen = strlen( pattern );
	fsize = smb_get_file_size( socket: socket, uid: uid, tid: tid, fid: fid );
	if(isnull( offset )){
		if( fsize < 180224 ){
			offset = 0;
		}
		else {
			offset = fsize - 180224;
		}
	}
	if(offset < 0){
		offset = fsize + offset;
	}
	start = offset;
	if(start < 0 || start > fsize){
		start = fsize / 2;
	}
	offset = start;
	chunk = 16384;
	for(i = 0;offset < fsize;i++){
		tmp = ReadAndX( socket: socket, uid: uid, tid: tid, fid: fid, count: chunk, off: offset );
		if(tmp){
			if( pattern == "build" ){
				tmp = str_replace( find: raw_string( 0 ), replace: "", string: tmp );
			}
			else {
				tmp = str_replace( find: raw_string( 0 ), replace: "?", string: tmp );
			}
			data += tmp;
			version = strstr( data, pattern );
			if(version){
				len = strlen( version );
				for(i = patlen;i < len;i++){
					if(!isnull( version[i] )){
						if( ( ord( version[i] ) < ord( "0" ) || ord( version[i] ) > ord( "9" ) ) && ( version[i] != "." && version[i] != "," && version[i] != " " && version[i] != "?" ) ){
							ver_len = strlen( ver );
							if(ver_len > 0 && ver[ver_len - 1] == "."){
								vers = split( buffer: ver, sep: ".", keep: FALSE );
								for _item in vers {
									retVal += NASLString( "." + _item );
								}
								retVal -= NASLString( "." );
								return retVal;
							}
							return ver;
						}
						else {
							if( version[i] == "," || version[i] == "." ){
								ver += ".";
							}
							else {
								if( ver && version[i] == "?" && version[i + 1] == "?" ){
									return ver;
								}
								else {
									if( version[i] == " " || version[i] == "?" ){
										}
									else {
										ver += version[i];
									}
								}
							}
						}
					}
				}
			}
			offset += chunk;
		}
	}
	return NULL;
}