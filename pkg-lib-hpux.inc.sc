__pkg_match = FALSE;
var __hpux_ssh_release, __hpux_ssh_pkgrev, __hpux_ssh_pkgsupersedes;
func hpux_get_ssh_release(  ){
	var rls;
	if( !isnull( __hpux_ssh_release ) ){
		rls = NASLString( __hpux_ssh_release );
	}
	else {
		rls = NASLString( get_kb_item( "ssh/login/release" ) );
		__hpux_ssh_release = rls;
	}
	return rls;
}
func hpux_get_ssh_pkgrev(  ){
	var pkgrev;
	if( !isnull( __hpux_ssh_pkgrev ) ){
		pkgrev = NASLString( __hpux_ssh_pkgrev );
	}
	else {
		pkgrev = NASLString( get_kb_item( "ssh/login/hp_pkgrev" ) );
		__hpux_ssh_pkgrev = pkgrev;
	}
	return pkgrev;
}
func hpux_get_ssh_pkgsupersedes(  ){
	var pkgsupersedes;
	if( !isnull( __hpux_ssh_pkgsupersedes ) ){
		pkgsupersedes = NASLString( __hpux_ssh_pkgsupersedes );
	}
	else {
		pkgsupersedes = NASLString( get_kb_item( "ssh/login/hp_pkgsupersedes" ) );
		__hpux_ssh_pkgsupersedes = pkgsupersedes;
	}
	return pkgsupersedes;
}
func ishpuxpkgvuln( pkg, revision, patch_list, rls ){
	var pkg, revision, patch_list, rls;
	var kbrls, pkgs_rev, inst_rev, patches, _patch, rc, report;
	kbrls = hpux_get_ssh_release();
	if(kbrls != rls){
		return NULL;
	}
	pkgs_rev = hpux_get_ssh_pkgrev();
	inst_rev = eregmatch( pattern: pkg + "(\\t+| +)?([a-zA-Z0-9.]+) ", string: chomp( pkgs_rev ) );
	if(isnull( inst_rev )){
		return NULL;
	}
	__pkg_match = TRUE;
	if(!isnull( patch_list )){
		patches = hpux_get_ssh_pkgsupersedes();
		for _patch in patch_list {
			if(!ContainsString( patches, _patch )){
				return "";
			}
		}
		return NULL;
	}
	rc = revcomp( a: inst_rev[2], b: revision );
	if(rc < 0){
		report = "Vulnerable package: " + pkg + "\n";
		report += "Installed version:  " + inst_rev[2] + "\n";
		report += "Fixed version:      " + revision + "\n\n";
		return report;
	}
	return NULL;
}

