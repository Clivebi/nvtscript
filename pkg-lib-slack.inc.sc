__pkg_match = FALSE;
var __slk_ssh_release, __slk_ssh_pkgs;
func slk_get_ssh_release(  ){
	var rls;
	if( !isnull( __slk_ssh_release ) ){
		rls = NASLString( __slk_ssh_release );
	}
	else {
		rls = NASLString( get_kb_item( "ssh/login/release" ) );
		__slk_ssh_release = rls;
	}
	return rls;
}
func slk_get_ssh_pkgs(  ){
	var pkgs;
	if( !isnull( __slk_ssh_pkgs ) ){
		pkgs = NASLString( __slk_ssh_pkgs );
	}
	else {
		pkgs = NASLString( get_kb_item( "ssh/login/slackpack" ) );
		__slk_ssh_pkgs = pkgs;
	}
	return pkgs;
}
func isslkpkgvuln( pkg, ver, rls ){
	var pkg, ver, rls;
	var kbrls, pkgs, narrowed, list, fixed_pkg, _inst_pkg, rc, report;
	kbrls = slk_get_ssh_release();
	if(kbrls != rls){
		return NULL;
	}
	pkgs = slk_get_ssh_pkgs();
	if(!pkgs){
		return NULL;
	}
	narrowed = egrep( pattern: "^" + pkg + "-[0-9]", string: pkgs );
	if(!narrowed){
		return NULL;
	}
	list = split( buffer: narrowed, sep: "\n", keep: FALSE );
	__pkg_match = TRUE;
	fixed_pkg = pkg + "-" + ver;
	for _inst_pkg in list {
		rc = revcomp( a: _inst_pkg, b: fixed_pkg );
		if(rc < 0){
			report = "Vulnerable package: " + pkg + "\n";
			report += "Installed version:  " + _inst_pkg + "\n";
			report += "Fixed version:      " + fixed_pkg + "\n\n";
			return report;
		}
	}
	return NULL;
}

