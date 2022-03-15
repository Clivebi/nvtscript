var __macos_ssh_osxname, __macos_ssh_osxversion;
func kb_get_ssh_osxname(  ){
	var name;
	if( !isnull( __macos_ssh_osxname ) ){
		name = NASLString( __macos_ssh_osxname );
	}
	else {
		name = NASLString( get_kb_item( "ssh/login/osx_name" ) );
		__macos_ssh_osxname = name;
	}
	return name;
}
func kb_get_ssh_osxversion(  ){
	var version;
	if( !isnull( __macos_ssh_osxversion ) ){
		version = NASLString( __macos_ssh_osxversion );
	}
	else {
		version = NASLString( get_kb_item( "ssh/login/osx_version" ) );
		__macos_ssh_osxversion = version;
	}
	return version;
}
func kb_check_macos_release( vers_regex, name_regex ){
	var vers_regex, name_regex;
	var os_name, os_ver;
	if(!vers_regex){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#vers_regex#-#check_ssh_macos_release" );
		return;
	}
	if(!name_regex){
		name_regex = "Mac OS X";
	}
	os_name = kb_get_ssh_osxname();
	if(!os_name || !egrep( string: os_name, pattern: name_regex )){
		return FALSE;
	}
	os_ver = kb_get_ssh_osxversion();
	if( !os_ver || !egrep( string: os_ver, pattern: vers_regex ) ) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}
func isosxpkgvuln( fixed, diff ){
	var fixed, diff;
	var list, max_diff, _i, s;
	list = get_kb_item( "ssh/login/osx_pkgs" );
	if(!list){
		exit( 0 );
	}
	max_diff = 0;
	list = split( list );
	for _i in keys( list ) {
		if(ContainsString( chomp( list[_i] ), fixed )){
			s = ( substr( chomp( list[_i] ), strlen( fixed ), strlen( fixed ) + strlen( diff ) - 1 ) );
			if(s > max_diff){
				max_diff = s;
			}
		}
	}
	if( diff > max_diff ) {
		return 1;
	}
	else {
		return 0;
	}
}
func pkg_in_list( name, version ){
	var name, version;
	var list, _i;
	list = get_kb_item( "ssh/login/osx_pkgs" );
	if(!list){
		exit( 0 );
	}
	list = split( list );
	for _i in keys( list ) {
		if(name == chomp( list[_i] )){
			if(version == 0 || version == chomp( list[_i + 1] )){
				return 1;
			}
		}
	}
	return 0;
}
func osx_rls_name( rls ){
	var rls;
	var r;
	r = eregmatch( pattern: "[a-z A-Z]+[0-9]+\\.[0-9]+", string: rls );
	return r[0];
}
func osx_ver( ver ){
	var ver;
	var v;
	v = eregmatch( pattern: "[0-9.]+", string: ver );
	return v[0];
}
func rlsnotsupported( rls, list ){
	var rls, list;
	var min, _ver, r;
	min = eregmatch( pattern: "[0-9]+.[0-9]+", string: list[0] );
	for _ver in list {
		r = eregmatch( pattern: "[0-9]+.[0-9]+", string: _ver );
		if(min[0] > r[0]){
			r = min;
		}
	}
	rls = eregmatch( pattern: "[0-9]+.[0-9]+", string: rls );
	if( rls[0] < min[0] ) {
		return 1;
	}
	else {
		return 0;
	}
}

