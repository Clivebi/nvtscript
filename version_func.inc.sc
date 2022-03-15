func version_is_less( version, test_version, icase, debug ){
	var version, test_version, icase, debug;
	if(!version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version#-#version_is_less" );
	}
	if(!test_version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#test_version#-#version_is_less" );
	}
	if(IsMatchRegexp( version, "^\\s+" ) || IsMatchRegexp( version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_less: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );
	}
	if(IsMatchRegexp( test_version, "^\\s+" ) || IsMatchRegexp( test_version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_less: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );
	}
	return ( version_test( version: version, test_version: test_version, less: TRUE, icase: icase, debug: debug ) );
}
func version_is_equal( version, test_version, icase, debug ){
	var version, test_version, icase, debug;
	if(!version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version#-#version_is_equal" );
	}
	if(!test_version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#test_version#-#version_is_equal" );
	}
	if(IsMatchRegexp( version, "^\\s+" ) || IsMatchRegexp( version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_equal: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );
	}
	if(IsMatchRegexp( test_version, "^\\s+" ) || IsMatchRegexp( test_version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_equal: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );
	}
	return ( version_test( version: version, test_version: test_version, less: FALSE, icase: icase, debug: debug ) );
}
func version_test( version, test_version, less, icase, debug ){
	var version, test_version, less, icase, debug;
	var ver_sep, ver_ary, test_ary, _i, r, s, test_prerelease, char_found, ver_prerelease;
	if(isnull( version ) || version == "" || version == 0 || version == "0" || version == "unknown" || version == "Unknown" || version == "."){
		return FALSE;
	}
	if(isnull( icase )){
		icase = TRUE;
	}
	if(icase){
		version = tolower( version );
		test_version = tolower( test_version );
	}
	if(debug){
		display( "DEBUG: Initial version: " + version + " and test_version: " + test_version );
	}
	ver_sep = ".";
	version = ereg_replace( pattern: "( |\\-|\\.\\.|_|update_)", string: version, replace: "." );
	if(IsMatchRegexp( version, "[0-9]update[0-9]" )){
		version = ereg_replace( pattern: "update", string: version, replace: ".update." );
	}
	version = ereg_replace( pattern: "-b[0-9][0-9]", string: version, replace: "" );
	test_version = ereg_replace( pattern: "( |\\-|\\.\\.|_)", string: test_version, replace: "." );
	if(debug){
		display( "DEBUG: version: " + version + " and test_version: " + test_version + " after applying standard separator" );
	}
	version = ereg_replace( pattern: "([0-9])([A-Za-z])", string: version, replace: "\\1.\\2" );
	test_version = ereg_replace( pattern: "([0-9])([A-Za-z])", string: test_version, replace: "\\1.\\2" );
	if(debug){
		display( "DEBUG: version: " + version + " and test_version: " + test_version + " after adding dots" );
	}
	ver_ary = split( buffer: version, sep: ver_sep, keep: FALSE );
	test_ary = split( buffer: test_version, sep: ver_sep, keep: FALSE );
	for(;max_index( ver_ary ) < max_index( test_ary );){
		ver_ary[max_index( ver_ary )] = "0";
	}
	for(;max_index( ver_ary ) > max_index( test_ary );){
		test_ary[max_index( test_ary )] = "0";
	}
	for _i in keys( test_ary ) {
		r = eregmatch( pattern: "([0-9]+)", string: test_ary[_i] );
		s = eregmatch( pattern: "([A-Za-z])", string: test_ary[_i] );
		test_prerelease = eregmatch( pattern: "(rc|alpha|beta)([0-9]+)", string: test_ary[_i], icase: TRUE );
		if( isnull( s ) ){
			test_ary[_i] = int( r[0] ) * 128;
			char_found = FALSE;
		}
		else {
			if( isnull( test_prerelease ) ){
				test_ary[_i] = ( int( r[0] ) * 128 ) + ord( s[0] );
			}
			else {
				test_ary[_i] = test_prerelease[2];
			}
			char_found = TRUE;
		}
		r = eregmatch( pattern: "([0-9]+)", string: ver_ary[_i] );
		s = eregmatch( pattern: "([A-Za-z])", string: ver_ary[_i] );
		ver_prerelease = eregmatch( pattern: "(rc|alpha|beta)([0-9]+)", string: ver_ary[_i], icase: TRUE );
		if( isnull( s ) ){
			ver_ary[_i] = int( r[0] ) * 128;
		}
		else {
			if( char_found ){
				if( isnull( ver_prerelease ) ){
					ver_ary[_i] = ( int( r[0] ) * 128 ) + ord( s[0] );
				}
				else {
					ver_ary[_i] = ver_prerelease[2];
				}
			}
			else {
				if( isnull( r ) ){
					ver_ary[_i] = ord( s[0] );
				}
				else {
					if(!less){
						return FALSE;
					}
					ver_ary[_i] = int( r[0] ) * 128;
				}
			}
		}
		if( less ){
			if(ver_ary[_i] < test_ary[_i]){
				return TRUE;
			}
			if(ver_ary[_i] > test_ary[_i]){
				return FALSE;
			}
		}
		else {
			if(ver_ary[_i] != test_ary[_i]){
				return FALSE;
			}
		}
	}
	if( less ) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}
func version_is_less_equal( version, test_version, icase, debug ){
	var version, test_version, icase, debug;
	if(!version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version#-#version_is_less_equal" );
	}
	if(!test_version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#test_version#-#version_is_less_equal" );
	}
	if(IsMatchRegexp( version, "^\\s+" ) || IsMatchRegexp( version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_less_equal: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );
	}
	if(IsMatchRegexp( test_version, "^\\s+" ) || IsMatchRegexp( test_version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_less_equal: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );
	}
	if(version_is_equal( version: version, test_version: test_version, icase: icase, debug: debug )){
		return TRUE;
	}
	if(version_is_less( version: version, test_version: test_version, icase: icase, debug: debug )){
		return TRUE;
	}
	return FALSE;
}
func version_is_greater_equal( version, test_version, icase, debug ){
	var version, test_version, icase, debug;
	if(!version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version#-#version_is_greater_equal" );
	}
	if(!test_version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#test_version#-#version_is_greater_equal" );
	}
	if(IsMatchRegexp( version, "^\\s+" ) || IsMatchRegexp( version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_greater_equal: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );
	}
	if(IsMatchRegexp( test_version, "^\\s+" ) || IsMatchRegexp( test_version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_greater_equal: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );
	}
	if(version_is_equal( version: version, test_version: test_version, icase: icase, debug: debug )){
		return TRUE;
	}
	if(version_is_less( version: test_version, test_version: version, icase: icase, debug: debug )){
		return TRUE;
	}
	return FALSE;
}
func version_is_greater( version, test_version, icase, debug ){
	var version, test_version, icase, debug;
	if(!version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version#-#version_is_greater" );
	}
	if(!test_version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#test_version#-#version_is_greater" );
	}
	if(IsMatchRegexp( version, "^\\s+" ) || IsMatchRegexp( version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_greater: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );
	}
	if(IsMatchRegexp( test_version, "^\\s+" ) || IsMatchRegexp( test_version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_is_greater: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );
	}
	if(version_is_less( version: test_version, test_version: version, icase: icase, debug: debug )){
		return TRUE;
	}
	return FALSE;
}
func version_in_range( version, test_version, test_version2, icase, debug ){
	var version, test_version, test_version2, icase, debug;
	if(!version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version#-#version_in_range" );
	}
	if(!test_version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#test_version#-#version_in_range" );
	}
	if(!test_version2){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#test_version2#-#version_in_range" );
	}
	if(IsMatchRegexp( version, "^\\s+" ) || IsMatchRegexp( version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_in_range: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );
	}
	if(IsMatchRegexp( test_version, "^\\s+" ) || IsMatchRegexp( test_version, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_in_range: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );
	}
	if(IsMatchRegexp( test_version2, "^\\s+" ) || IsMatchRegexp( test_version2, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#version_in_range: Trailing / leading space passed to 'test_version2' parameter which might show an unexpected behavior." );
	}
	if(version_is_greater_equal( version: version, test_version: test_version, icase: icase, debug: debug )){
		if(version_is_less_equal( version: version, test_version: test_version2, icase: icase, debug: debug )){
			return TRUE;
		}
	}
	return FALSE;
}
func get_version_from_kb( port, app ){
	var port, app;
	var version, matches, vers;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#get_version_from_kb" );
	}
	if(!app){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#app#-#get_version_from_kb" );
	}
	if(isnull( port ) || isnull( app )){
		return FALSE;
	}
	if(!version = get_kb_item( "www/" + port + "/" + app )){
		return FALSE;
	}
	if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
		return FALSE;
	}
	vers = matches[1];
	if(isnull( vers )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#vers#-#get_version_from_kb" );
		return FALSE;
	}
	if(vers == "unknown" || vers == "Unknown"){
		return FALSE;
	}
	return NASLString( vers );
}
func get_dir_from_kb( port, app ){
	var port, app;
	var version, matches, dir;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#get_dir_from_kb" );
	}
	if(!app){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#app#-#get_dir_from_kb" );
	}
	if(isnull( port ) || isnull( app )){
		return FALSE;
	}
	if(!version = get_kb_item( "www/" + port + "/" + app )){
		return FALSE;
	}
	if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
		return FALSE;
	}
	dir = matches[2];
	if(isnull( dir )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dir#-#get_dir_from_kb" );
		return FALSE;
	}
	return NASLString( dir );
}
func get_samba_version(  ){
	var lanman, version;
	if(!lanman = get_kb_item( "SMB/NativeLanManager" )){
		return FALSE;
	}
	if(!ContainsString( lanman, "Samba" )){
		return FALSE;
	}
	if(!version = eregmatch( pattern: "Samba ([0-9.]+)", string: lanman )){
		return FALSE;
	}
	if(isnull( version[1] )){
		return FALSE;
	}
	return version[1];
}
func report_fixed_ver( installed_version, installed_build, installed_patch, vulnerable_range, file_checked, file_version, reg_checked, fixed_version, fixed_build, fixed_patch, extra, install_path, install_url ){
	var installed_version, installed_build, installed_patch, vulnerable_range, file_checked, file_version;
	var reg_checked, fixed_version, fixed_build, fixed_patch, extra, install_path, install_url;
	var report;
	if(!installed_version && !file_checked){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#installed_version/file_checked#-#report_fixed_ver" );
	}
	if(!fixed_version && !vulnerable_range){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#fixed_version/vulnerable_range#-#report_fixed_ver" );
	}
	if(installed_version){
		report += "Installed version: " + installed_version + "\n";
	}
	if(installed_build){
		report += "Installed build:   " + installed_build + "\n";
	}
	if(installed_patch){
		report += "Installed patch:   " + installed_patch + "\n";
	}
	if(fixed_version){
		report += "Fixed version:     " + fixed_version + "\n";
	}
	if(fixed_build){
		report += "Fixed build:       " + fixed_build + "\n";
	}
	if(fixed_patch){
		report += "Fixed patch:       " + fixed_patch + "\n";
	}
	if(vulnerable_range){
		report += "Vulnerable range:  " + vulnerable_range + "\n";
	}
	if(file_checked){
		report += "File checked:      " + file_checked + "\n";
	}
	if(file_version){
		report += "File version:      " + file_version + "\n";
	}
	if(reg_checked){
		report += "Reg-Key checked:   " + reg_checked + "\n";
	}
	if(install_path){
		report += "Installation\n";
		report += "path / port:       " + install_path + "\n";
	}
	if(install_url){
		report += "Installation URL:  " + install_url + "\n";
	}
	if(extra){
		report += "\n" + extra + "\n";
	}
	return report;
}

