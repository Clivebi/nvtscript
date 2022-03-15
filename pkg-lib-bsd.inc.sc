__pkg_match = FALSE;
func portver( pkg ){
	var pkg;
	var pkgs, narrowed, list, _package, pat, matches;
	pkgs = get_kb_item( "ssh/login/freebsdpkg" );
	if(!pkgs){
		return ( NULL );
	}
	narrowed = egrep( pattern: "^" + pkg + "-[0-9]", string: pkgs );
	if(!narrowed){
		return ( NULL );
	}
	__pkg_match = TRUE;
	list = split( buffer: narrowed, sep: "\n", keep: FALSE );
	for _package in list {
		pat = NASLString( "^", pkg, "-([^ -]+) (.*)$" );
		matches = eregmatch( pattern: pat, string: _package );
		if(!isnull( matches )){
			return ( matches[1] );
		}
	}
	return ( NULL );
}
func patchlevelcmp( rel, patchlevel ){
	var rel, patchlevel;
	var kbrel, kbpatchlevel;
	kbrel = get_kb_item( "ssh/login/freebsdrel" );
	if(kbrel != rel){
		return ( 0 );
	}
	kbpatchlevel = int( get_kb_item( "ssh/login/freebsdpatchlevel" ) );
	if( kbpatchlevel < int( patchlevel ) ){
		return ( -1 );
	}
	else {
		if( kbpatchlevel > int( patchlevel ) ){
			return ( 1 );
		}
		else {
			return ( 0 );
		}
	}
}

