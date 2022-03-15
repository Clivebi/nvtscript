var __wmi_file_search_disabled;
func wmi_file_is_file_search_disabled(  ){
	var is_file_search_disabled;
	if( !isnull( __wmi_file_search_disabled ) ){
		is_file_search_disabled = __wmi_file_search_disabled;
	}
	else {
		is_file_search_disabled = get_kb_item( "win/lsc/disable_wmi_search" );
		if( is_file_search_disabled ) {
			__wmi_file_search_disabled = TRUE;
		}
		else {
			__wmi_file_search_disabled = FALSE;
		}
		is_file_search_disabled = __wmi_file_search_disabled;
	}
	return is_file_search_disabled;
}
func wmi_file_subdir( handle, dirPath, includeHeader ){
	var handle, dirPath, includeHeader, query, queryRes, splitList, _list, _splitItem;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_subdir" );
		return NULL;
	}
	if(!dirPath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath#-#wmi_file_subdir" );
		return NULL;
	}
	query = "SELECT Name FROM Win32_Directory WHERE Path = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	if(includeHeader){
		return splitList;
	}
	_list = make_list();
	for _splitItem in splitList {
		if(_splitItem == "Name"){
			continue;
		}
		_list = make_list( _list,
			 _splitItem );
	}
	return _list;
}
func wmi_file_check_dir_exists( handle, dirPath ){
	var handle, dirPath, query, queryRes;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_check_dir_exists" );
		return NULL;
	}
	if(!dirPath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath#-#wmi_file_check_dir_exists" );
		return NULL;
	}
	query = "SELECT Caption FROM Win32_Directory WHERE Name = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if( !queryRes ) {
			return FALSE;
		}
		else {
			return TRUE;
		}
	}
}
func wmi_file_is_subdir_readable( handle, dirPath, includeHeader ){
	var handle, dirPath, includeHeader, query, queryRes, splitList, _array, _splitItem, _item;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_is_subdir_readable" );
		return NULL;
	}
	if(!dirPath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath#-#wmi_file_is_subdir_readable" );
		return NULL;
	}
	query = "SELECT Name, Readable FROM Win32_Directory WHERE Path = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	_array = make_array();
	for _splitItem in splitList {
		if(_splitItem == "Name|Readable" && !includeHeader){
			continue;
		}
		_item = split( buffer: _splitItem, sep: "|", keep: FALSE );
		_array[_item[0]] = _item[1];
	}
	return _array;
}
func wmi_file_is_subdir_writeable( handle, dirPath, includeHeader ){
	var handle, dirPath, includeHeader, query, queryRes, splitList, _array, _splitItem, _item;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_is_subdir_writeable" );
		return NULL;
	}
	if(!dirPath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath#-#wmi_file_is_subdir_writeable" );
		return NULL;
	}
	query = "SELECT NName, Writeable FROM Win32_Directory WHERE Path = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	_array = make_array();
	for _splitItem in splitList {
		if(_splitItem == "Name|Writeable" && !includeHeader){
			continue;
		}
		_item = split( buffer: _splitItem, sep: "|", keep: FALSE );
		_array[_item[0]] = _item[1];
	}
	return _array;
}
func wmi_file_filelist( handle, dirPath, includeHeader ){
	var handle, dirPath, includeHeader, query, queryRes, splitList, _list, _splitItem;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_filelist" );
		return NULL;
	}
	if(!dirPath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath#-#wmi_file_filelist" );
		return NULL;
	}
	query = "SELECT Name FROM CIM_DataFile WHERE Path = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	if(includeHeader){
		return splitList;
	}
	_list = make_list();
	for _splitItem in splitList {
		if(_splitItem == "Name"){
			continue;
		}
		_list = make_list( _list,
			 _splitItem );
	}
	return _list;
}
func wmi_file_filesize( handle, filePath, includeHeader ){
	var handle, filePath, query, includeHeader, query, queryRes, splitList, _array, _splitItem, _item;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_filesize" );
		return NULL;
	}
	if(!filePath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#filePath#-#wmi_file_filesize" );
		return NULL;
	}
	query = "SELECT FileSize, Name FROM CIM_DataFile WHERE Name = " + raw_string( 0x22 ) + filePath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	_array = make_array();
	for _splitItem in splitList {
		if(_splitItem == "FileSize|Name" && !includeHeader){
			continue;
		}
		_item = split( buffer: _splitItem, sep: "|", keep: FALSE );
		_array[_item[0]] = _item[1];
	}
	return _array;
}
func wmi_file_get_extnfile( handle, dirPath, fileExtn, includeHeader ){
	var handle, dirPath, fileExtn, includeHeader, query, queryRes, splitList, _list, _splitItem;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_get_extnfile" );
		return NULL;
	}
	if(!dirPath && !fileExtn){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath and fileExtn#-#wmi_file_get_extnfile" );
		return NULL;
	}
	if(dirPath && !fileExtn){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath passed but not fileExtn#-#wmi_file_get_extnfile" );
		return NULL;
	}
	if( dirPath && fileExtn ){
		query = "SELECT Name FROM CIM_DataFile WHERE Path = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 ) + " AND Extension = " + raw_string( 0x22 ) + fileExtn + raw_string( 0x22 );
	}
	else {
		if(fileExtn){
			query = "SELECT Name FROM CIM_DataFile WHERE Extension = " + raw_string( 0x22 ) + fileExtn + raw_string( 0x22 );
		}
	}
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	if(includeHeader){
		return splitList;
	}
	_list = make_list();
	for _splitItem in splitList {
		if(_splitItem == "Name"){
			continue;
		}
		_list = make_list( _list,
			 _splitItem );
	}
	return _list;
}
func wmi_file_check_file_exists( handle, filePath ){
	var handle, filePath, query, queryRes;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_check_file_exists" );
		return NULL;
	}
	if(!filePath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#filePath#-#wmi_file_check_file_exists" );
		return NULL;
	}
	query = "SELECT Name FROM CIM_DataFile WHERE Name = " + raw_string( 0x22 ) + filePath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if( !queryRes ) {
			return FALSE;
		}
		else {
			return TRUE;
		}
	}
}
func wmi_file_file_search( handle, dirPath, dirPathLike, fileName, fileExtn, includeHeader ){
	var handle, dirPath, fileName, fileExtn, includeHeader, query, queryRes, splitList, _list, _splitItem;
	var kb_proxy_key, kb_proxy_key_list;
	if(wmi_file_is_file_search_disabled()){
		return NULL;
	}
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_file_search" );
		return NULL;
	}
	if(!dirPath && !dirPathLike && !fileName && !fileExtn){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath, dirPathLike, fileName and fileExtn#-#wmi_file_file_search" );
		return NULL;
	}
	if(dirPath && dirPathLike){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#wmi_file_file_search: dirPath and dirPathLike passed but only one of both can be used" );
		return NULL;
	}
	if(dirPath && ( !fileName && !fileExtn )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath passed but not fileName and fileExtn#-#wmi_file_file_search" );
		return NULL;
	}
	if(dirPathLike && ( !fileName && !fileExtn )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPathLike passed but not fileName and fileExtn#-#wmi_file_file_search" );
		return NULL;
	}
	if(fileExtn && ( !fileName && !dirPath && !dirPathLike )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#fileExtn passed but not fileName and dirPath/dirPathLike#-#wmi_file_file_search" );
		return NULL;
	}
	if(fileExtn && !fileName){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#fileExtn passed but not fileName#-#wmi_file_file_search" );
		return NULL;
	}
	if( dirPath && fileName && fileExtn ){
		kb_proxy_key = "WMI//wmi_file_file_search_cache//by_dirpath_filename_fileextn//" + tolower( dirPath ) + "//" + tolower( fileName ) + "//" + tolower( fileExtn );
	}
	else {
		if( dirPathLike && fileName && fileExtn ){
			kb_proxy_key = "WMI//wmi_file_file_search_cache//by_dirpathlike_filename_fileextn//" + tolower( dirPathLike ) + "//" + tolower( fileName ) + "//" + tolower( fileExtn );
		}
		else {
			if( fileName && fileExtn ){
				kb_proxy_key = "WMI//wmi_file_file_search_cache//by_filename_fileextn//" + tolower( fileName ) + "//" + tolower( fileExtn );
			}
			else {
				if(fileName){
					kb_proxy_key = "WMI//wmi_file_file_search_cache//by_filename//" + tolower( fileName );
				}
			}
		}
	}
	if( includeHeader ) {
		kb_proxy_list = get_kb_list( kb_proxy_key + "//withheader" );
	}
	else {
		kb_proxy_list = get_kb_list( kb_proxy_key + "//withoutheader" );
	}
	if(!isnull( kb_proxy_list ) || kb_proxy_list){
		return kb_proxy_list;
	}
	if( dirPath && fileName && fileExtn ){
		query = "SELECT Name FROM CIM_DataFile WHERE Path = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 ) + " AND FileName = " + raw_string( 0x22 ) + fileName + raw_string( 0x22 ) + " AND Extension = " + raw_string( 0x22 ) + fileExtn + raw_string( 0x22 );
	}
	else {
		if( dirPathLike && fileName && fileExtn ){
			query = "SELECT Name FROM CIM_DataFile WHERE Path LIKE " + raw_string( 0x22 ) + dirPathLike + raw_string( 0x22 ) + " AND FileName = " + raw_string( 0x22 ) + fileName + raw_string( 0x22 ) + " AND Extension = " + raw_string( 0x22 ) + fileExtn + raw_string( 0x22 );
		}
		else {
			if( fileName && fileExtn ){
				query = "SELECT Name FROM CIM_DataFile WHERE FileName = " + raw_string( 0x22 ) + fileName + raw_string( 0x22 ) + " AND Extension = " + raw_string( 0x22 ) + fileExtn + raw_string( 0x22 );
			}
			else {
				if(fileName){
					query = "SELECT Name FROM CIM_DataFile WHERE FileName = " + raw_string( 0x22 ) + fileName + raw_string( 0x22 );
				}
			}
		}
	}
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	_list = make_list();
	splitList = split( buffer: queryRes, keep: FALSE );
	for _splitItem in splitList {
		if( _splitItem == "Name" ){
			set_kb_item( name: kb_proxy_key + "//withheader", value: _splitItem );
			if(!includeHeader){
				continue;
			}
		}
		else {
			set_kb_item( name: kb_proxy_key + "//withheader", value: _splitItem );
			set_kb_item( name: kb_proxy_key + "//withoutheader", value: _splitItem );
		}
		_list = make_list( _list,
			 _splitItem );
	}
	return _list;
}
func wmi_file_fileinfo( handle, filePath ){
	var handle, filePath, query, queryRes, splitList, propList, returnArray, i, desc, j;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_fileinfo" );
		return NULL;
	}
	if(!filePath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#filePath#-#wmi_file_fileinfo" );
		return NULL;
	}
	query = "SELECT * FROM CIM_DataFile WHERE Name = " + raw_string( 0x22 ) + filePath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	propList = split( buffer: splitList[0], sep: "|", keep: FALSE );
	returnArray = make_array();
	for(i = 1;i < max_index( splitList );i++){
		desc = split( buffer: splitList[i], sep: "|", keep: FALSE );
		for(j = 0;j < max_index( propList );j++){
			returnArray[propList[j]] = desc[j];
		}
	}
	return returnArray;
}
func wmi_file_fileversion( handle, filePath, dirPath, dirPathLike, fileName, fileExtn, includeHeader ){
	var handle, filePath, dirPath, dirPathLike, fileName, fileExtn, includeHeader, query, queryRes, splitList, _array, _splitItem, _item;
	var kb_proxy_key, kb_proxy_list;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_fileversion" );
		return NULL;
	}
	if(!filePath && !dirPath && !dirPathLike && !fileName && !fileExtn){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#filePath, dirPath, dirPathLike, fileName and fileExtn#-#wmi_file_fileversion" );
		return NULL;
	}
	if(!filePath && wmi_file_is_file_search_disabled()){
		return NULL;
	}
	if(filePath && ( dirPath || dirPathLike || fileName || fileExtn )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#wmi_file_fileversion: filePath can be used only alone without other parameters" );
		return NULL;
	}
	if(dirPath && dirPathLike){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#wmi_file_fileversion: dirPath and dirPathLike passed but only one of both can be used" );
		return NULL;
	}
	if(dirPath && ( !fileName && !fileExtn )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath passed but not fileName and fileExtn#-#wmi_file_fileversion" );
		return NULL;
	}
	if(dirPathLike && ( !fileName && !fileExtn )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPathLike passed but not fileName and fileExtn#-#wmi_file_fileversion" );
		return NULL;
	}
	if(fileExtn && ( !fileName && !dirPath && !dirPathLike )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#fileExtn passed but not fileName and dirPath/dirPathLike#-#wmi_file_fileversion" );
		return NULL;
	}
	if(fileExtn && !fileName){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#fileExtn passed but not fileName#-#wmi_file_fileversion" );
		return NULL;
	}
	if( filePath ){
		kb_proxy_key = "WMI//wmi_file_fileversion_cache//by_filepath//" + tolower( filePath );
	}
	else {
		if( dirPath && fileName && fileExtn ){
			kb_proxy_key = "WMI//wmi_file_fileversion_cache//by_dirpath_filename_fileextn//" + tolower( dirPath ) + "//" + tolower( fileName ) + "//" + tolower( fileExtn );
		}
		else {
			if( dirPathLike && fileName && fileExtn ){
				kb_proxy_key = "WMI//wmi_file_fileversion_cache//by_dirpathlike_filename_fileextn//" + tolower( dirPathLike ) + "//" + tolower( fileName ) + "//" + tolower( fileExtn );
			}
			else {
				if( fileName && fileExtn ){
					kb_proxy_key = "WMI//wmi_file_fileversion_cache//by_filename_fileextn//" + tolower( fileName ) + "//" + tolower( fileExtn );
				}
				else {
					if(fileName){
						kb_proxy_key = "WMI//wmi_file_fileversion_cache//by_filename//" + tolower( fileName );
					}
				}
			}
		}
	}
	if( includeHeader ) {
		kb_proxy_list = get_kb_list( kb_proxy_key + "//withheader" );
	}
	else {
		kb_proxy_list = get_kb_list( kb_proxy_key + "//withoutheader" );
	}
	if(!isnull( kb_proxy_list ) || kb_proxy_list){
		_array = make_array();
		for _splitItem in kb_proxy_list {
			_item = split( buffer: _splitItem, sep: "#---#", keep: FALSE );
			_array[_item[0]] = _item[1];
		}
		return _array;
	}
	if( filePath ){
		query = "SELECT Name, Version FROM CIM_DataFile WHERE Name = " + raw_string( 0x22 ) + filePath + raw_string( 0x22 );
	}
	else {
		if( dirPath && fileName && fileExtn ){
			query = "SELECT Name, Version FROM CIM_DataFile WHERE Path = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 ) + " AND FileName = " + raw_string( 0x22 ) + fileName + raw_string( 0x22 ) + " AND Extension = " + raw_string( 0x22 ) + fileExtn + raw_string( 0x22 );
		}
		else {
			if( dirPathLike && fileName && fileExtn ){
				query = "SELECT Name, Version FROM CIM_DataFile WHERE Path LIKE " + raw_string( 0x22 ) + dirPathLike + raw_string( 0x22 ) + " AND FileName = " + raw_string( 0x22 ) + fileName + raw_string( 0x22 ) + " AND Extension = " + raw_string( 0x22 ) + fileExtn + raw_string( 0x22 );
			}
			else {
				if( fileName && fileExtn ){
					query = "SELECT Name, Version FROM CIM_DataFile WHERE FileName = " + raw_string( 0x22 ) + fileName + raw_string( 0x22 ) + " AND Extension = " + raw_string( 0x22 ) + fileExtn + raw_string( 0x22 );
				}
				else {
					if(fileName){
						query = "SELECT Name, Version FROM CIM_DataFile WHERE FileName = " + raw_string( 0x22 ) + fileName + raw_string( 0x22 );
					}
				}
			}
		}
	}
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	_array = make_array();
	splitList = split( buffer: queryRes, keep: FALSE );
	for _splitItem in splitList {
		_item = split( buffer: _splitItem, sep: "|", keep: FALSE );
		if( _item[0] == "Name" && _item[1] == "Version" ){
			set_kb_item( name: kb_proxy_key + "//withheader", value: _item[0] + "#---#" + _item[1] );
			if(!includeHeader){
				continue;
			}
		}
		else {
			set_kb_item( name: kb_proxy_key + "//withheader", value: _item[0] + "#---#" + _item[1] );
			set_kb_item( name: kb_proxy_key + "//withoutheader", value: _item[0] + "#---#" + _item[1] );
		}
		_array[_item[0]] = _item[1];
	}
	return _array;
}
func wmi_file_filecreationdate( handle, filePath ){
	var handle, filePath, query, queryRes, splitList, splitList, _splitItem, _item;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_filecreationdate" );
		return NULL;
	}
	if(!filePath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#filePath#-#wmi_file_filecreationdate" );
		return NULL;
	}
	query = "SELECT CreationDate, Name FROM CIM_DataFile WHERE Name = " + raw_string( 0x22 ) + filePath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	for _splitItem in splitList {
		if(_splitItem == "CreationDate|Name"){
			continue;
		}
		_item = split( buffer: _splitItem, sep: "|", keep: FALSE );
		return _item[0];
	}
	return NASLString( "unknown" );
}
func wmi_file_filemodifieddate( handle, filePath ){
	var handle, filePath, query, queryRes, splitList, splitList, _splitItem, _item;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_filemodifieddate" );
		return NULL;
	}
	if(!filePath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#filePath#-#wmi_file_filemodifieddate" );
		return NULL;
	}
	query = "SELECT LastModified, Name FROM CIM_DataFile WHERE Name = " + raw_string( 0x22 ) + filePath + raw_string( 0x22 );
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	for _splitItem in splitList {
		if(_splitItem == "LastModified|Name"){
			continue;
		}
		_item = split( buffer: _splitItem, sep: "|", keep: FALSE );
		return _item[0];
	}
	return NASLString( "unknown" );
}
func wmi_file_is_file_readable( handle, dirPath, filePath, includeHeader ){
	var handle, dirPath, filePath, includeHeader, query, queryRes, splitList, _array, _splitItem;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_is_file_readable" );
		return NULL;
	}
	if(!dirPath && !filePath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath and filePath#-#wmi_file_is_file_readable" );
		return NULL;
	}
	if( dirPath ) {
		query = "SELECT Name, Readable FROM CIM_DataFile WHERE Path = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 );
	}
	else {
		query = "SELECT Name, Readable FROM CIM_DataFile WHERE Name = " + raw_string( 0x22 ) + filePath + raw_string( 0x22 );
	}
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	_array = make_array();
	for _splitItem in splitList {
		if(_splitItem == "Name|Readable" && !includeHeader){
			continue;
		}
		_item = split( buffer: _splitItem, sep: "|", keep: FALSE );
		_array[_item[0]] = _item[1];
	}
	return _array;
}
func wmi_file_is_file_writeable( handle, dirPath, filePath, includeHeader ){
	var handle, dirPath, filePath, includeHeader, query, queryRes, splitList, _array, _splitItem;
	if(isnull( handle )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#handle#-#wmi_file_is_file_writeable" );
		return NULL;
	}
	if(!dirPath && !filePath){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dirPath and filePath#-#wmi_file_is_file_writeable" );
		return NULL;
	}
	if( dirPath ) {
		query = "SELECT Name, Writeable FROM CIM_DataFile WHERE Path = " + raw_string( 0x22 ) + dirPath + raw_string( 0x22 );
	}
	else {
		query = "SELECT Name, Writeable FROM CIM_DataFile WHERE Name = " + raw_string( 0x22 ) + filePath + raw_string( 0x22 );
	}
	queryRes = wmi_query( wmi_handle: handle, query: query );
	if( ContainsString( queryRes, "NTSTATUS" ) ) {
		return NULL;
	}
	else {
		if(!queryRes){
			return FALSE;
		}
	}
	splitList = split( buffer: queryRes, keep: FALSE );
	_array = make_array();
	for _splitItem in splitList {
		if(_splitItem == "Name|Writeable" && !includeHeader){
			continue;
		}
		_item = split( buffer: _splitItem, sep: "|", keep: FALSE );
		_array[_item[0]] = _item[1];
	}
	return _array;
}

