__pkg_match = FALSE;
var __dpkg_ssh_release, __dpkg_ssh_pkgs, __dpkg_kernel_overwrite, __dpkg_kernel_uname;
func dpkg_check_kernel_overwrite( vuln_pkg, installed_ver, fixed_ver ){
	var vuln_pkg, installed_ver, fixed_ver;
	var overwrite_enabled, report, kernel_uname;
	if(!vuln_pkg){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dpkg_check_kernel_overwrite#-#vuln_pkg" );
		return FALSE;
	}
	if(!installed_ver){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dpkg_check_kernel_overwrite#-#installed_ver" );
		return FALSE;
	}
	if(!fixed_ver){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dpkg_check_kernel_overwrite#-#fixed_ver" );
		return FALSE;
	}
	report = "Vulnerable package: " + vuln_pkg + "\n";
	report += "Installed version:  " + installed_ver + "\n";
	report += "Fixed version:      " + fixed_ver + "\n\n";
	if(!IsMatchRegexp( vuln_pkg, "^(linux-(cloud-tools|compiler-gcc|doc|headers|image|kbuild|manual|perf|source|support|)-|xen-linux-system-|linux-libc-dev|linux-cpupower)" )){
		return report;
	}
	if( isnull( __dpkg_kernel_overwrite ) ){
		overwrite_enabled = get_kb_item( "ssh/login/kernel_reporting_overwrite/enabled" );
		if( !overwrite_enabled ) {
			overwrite_enabled = FALSE;
		}
		else {
			overwrite_enabled = TRUE;
		}
		__dpkg_kernel_overwrite = overwrite_enabled;
	}
	else {
		overwrite_enabled = __dpkg_kernel_overwrite;
	}
	if(!overwrite_enabled){
		return report;
	}
	if( isnull( __dpkg_kernel_uname ) ){
		kernel_uname = get_kb_item( "ssh/login/uname" );
		if(!kernel_uname){
			kernel_uname = FALSE;
		}
		__dpkg_kernel_uname = kernel_uname;
	}
	else {
		kernel_uname = __dpkg_kernel_uname;
	}
	if(!kernel_uname){
		return report;
	}
	if(ContainsString( kernel_uname, installed_ver )){
		return report;
	}
	set_kb_item( name: "ssh/login/inactive_kernel_vulns/available", value: TRUE );
	set_kb_item( name: "ssh/login/inactive_kernel_vulns/reports/" + get_script_oid() + "/" + vuln_pkg, value: report );
	return NULL;
}
func dpkg_get_ssh_release(  ){
	var rls;
	if( !isnull( __dpkg_ssh_release ) ){
		rls = NASLString( __dpkg_ssh_release );
	}
	else {
		rls = NASLString( get_kb_item( "ssh/login/release" ) );
		__dpkg_ssh_release = rls;
	}
	return rls;
}
func dpkg_get_ssh_pkgs(  ){
	var pkgs;
	if( !isnull( __dpkg_ssh_pkgs ) ){
		pkgs = NASLString( __dpkg_ssh_pkgs );
	}
	else {
		pkgs = NASLString( get_kb_item( "ssh/login/packages" ) );
		__dpkg_ssh_pkgs = pkgs;
	}
	return pkgs;
}
func dpkgnorm( str, rls ){
	var str, rls, str2, m;
	if(!str){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dpkgnorm#-#str" );
		return NULL;
	}
	str2 = str_replace( find: "-lenny", string: str, replace: "lenny" );
	str2 = str_replace( find: "+lenny", string: str2, replace: "lenny" );
	str2 = str_replace( find: ".lenny", string: str2, replace: "lenny" );
	str2 = str_replace( find: "-squeeze", string: str, replace: "squeeze" );
	str2 = str_replace( find: "+squeeze", string: str2, replace: "squeeze" );
	str2 = str_replace( find: ".squeeze", string: str2, replace: "squeeze" );
	str2 = str_replace( find: "-wheezy", string: str, replace: "wheezy" );
	str2 = str_replace( find: "+wheezy", string: str2, replace: "wheezy" );
	str2 = str_replace( find: ".wheezy", string: str2, replace: "wheezy" );
	m = eregmatch( pattern: "^([0-9]:)?(.*)$", string: str2 );
	if(isnull( m )){
		return str2;
	}
	return ( m[2] );
}
func isdpkgvuln( pkg, ver, rls ){
	var kbrls, pkgs, pat, matches, rc, pat_a, pat_b, report;
	if(!pkg){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isdpkgvuln#-#pkg" );
		return NULL;
	}
	if(!ver){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isdpkgvuln#-#ver" );
		return NULL;
	}
	if(!rls){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isdpkgvuln#-#rls" );
		return NULL;
	}
	kbrls = dpkg_get_ssh_release();
	if(kbrls != rls){
		return NULL;
	}
	pkgs = dpkg_get_ssh_pkgs();
	if(!pkgs){
		return NULL;
	}
	pkgs = ereg_replace( pattern: ":i386", replace: "", string: pkgs );
	pkgs = ereg_replace( pattern: ":amd64", replace: "", string: pkgs );
	pat = NASLString( "ii  (", pkg, ") +([0-9]:)?([^ ]+)" );
	matches = eregmatch( pattern: pat, string: pkgs );
	if(isnull( matches )){
		return NULL;
	}
	__pkg_match = TRUE;
	pat_a = dpkgnorm( str: matches[3], rls: rls );
	pat_b = dpkgnorm( str: ver, rls: rls );
	rc = revcomp( a: pat_a, b: pat_b );
	if(rc < 0){
		report = dpkg_check_kernel_overwrite( vuln_pkg: pkg, installed_ver: matches[3], fixed_ver: ver );
		return report;
	}
	return NULL;
}

