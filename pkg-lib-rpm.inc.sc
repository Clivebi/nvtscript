__pkg_match = FALSE;
var __rpm_ssh_release, __rpm_ssh_rpms, __rpm_kernel_overwrite, __rpm_kernel_uname;
func rpm_check_kernel_overwrite( vuln_pkg, inst_pkg, fixed_pkg ){
	var vuln_pkg, inst_pkg, fixed_pkg;
	var overwrite_enabled, report, kernel_uname, inst_pkg_ver;
	if(!vuln_pkg){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#rpm_check_kernel_overwrite#-#vuln_pkg" );
		return FALSE;
	}
	if(!inst_pkg){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#rpm_check_kernel_overwrite#-#inst_pkg" );
		return FALSE;
	}
	if(!fixed_pkg){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#rpm_check_kernel_overwrite#-#fixed_pkg" );
		return FALSE;
	}
	report = "Vulnerable package: " + vuln_pkg + "\n";
	report += "Installed version:  " + inst_pkg + "\n";
	report += "Fixed version:      " + fixed_pkg + "\n\n";
	if(!IsMatchRegexp( vuln_pkg, "^kernel(-[0-9a-zA-Z_-]+)?$" )){
		return report;
	}
	if( isnull( __rpm_kernel_overwrite ) ){
		overwrite_enabled = get_kb_item( "ssh/login/kernel_reporting_overwrite/enabled" );
		if( !overwrite_enabled ) {
			overwrite_enabled = FALSE;
		}
		else {
			overwrite_enabled = TRUE;
		}
		__rpm_kernel_overwrite = overwrite_enabled;
	}
	else {
		overwrite_enabled = __rpm_kernel_overwrite;
	}
	if(!overwrite_enabled){
		return report;
	}
	if( isnull( __rpm_kernel_uname ) ){
		kernel_uname = get_kb_item( "ssh/login/uname" );
		if(!kernel_uname){
			kernel_uname = FALSE;
		}
		__rpm_kernel_uname = kernel_uname;
	}
	else {
		kernel_uname = __rpm_kernel_uname;
	}
	if(!kernel_uname){
		return report;
	}
	inst_pkg_ver = ereg_replace( string: inst_pkg, pattern: "\\.[0-9]+$", replace: "" );
	inst_pkg_ver = eregmatch( string: inst_pkg_ver, pattern: "^" + vuln_pkg + "-(.+)" );
	if(!inst_pkg_ver[1]){
		return report;
	}
	if(ContainsString( kernel_uname, inst_pkg_ver[1] )){
		return report;
	}
	set_kb_item( name: "ssh/login/inactive_kernel_vulns/available", value: TRUE );
	set_kb_item( name: "ssh/login/inactive_kernel_vulns/reports/" + get_script_oid() + "/" + inst_pkg, value: report );
	return NULL;
}
func rpm_get_ssh_release(  ){
	var rls;
	if( !isnull( __rpm_ssh_release ) ){
		rls = NASLString( __rpm_ssh_release );
	}
	else {
		rls = NASLString( get_kb_item( "ssh/login/release" ) );
		__rpm_ssh_release = rls;
	}
	return rls;
}
func rpm_get_ssh_rpms(  ){
	var rpms;
	if( !isnull( __rpm_ssh_rpms ) ){
		rpms = NASLString( __rpm_ssh_rpms );
	}
	else {
		rpms = NASLString( get_kb_item( "ssh/login/rpms" ) );
		__rpm_ssh_rpms = rpms;
	}
	return rpms;
}
func rpmnorm( inst_pkg, fixed_pkg, vuln_pkg ){
	var inst_pkg, fixed_pkg, vuln_pkg;
	var ret_array, _inst_pkg, _fixed_pkg, inst_pkg_substr, fixed_pkg_substr;
	var _inst_pkg_check, _fixed_pkg_check, norm_inst_pkg, norm_fixed_pkg, _comp;
	ret_array = make_array();
	_inst_pkg = inst_pkg;
	_fixed_pkg = fixed_pkg;
	inst_pkg_substr = substr( _inst_pkg, strlen( vuln_pkg ) + 1, strlen( _inst_pkg ) );
	fixed_pkg_substr = substr( _fixed_pkg, strlen( vuln_pkg ) + 1, strlen( _fixed_pkg ) );
	if( IsMatchRegexp( fixed_pkg_substr, "el[0-9]{1}_[0-9]{1}" ) && !IsMatchRegexp( inst_pkg_substr, "el[0-9]{1}_[0-9]{1}" ) ) {
		fixed_pkg_substr = str_replace( string: fixed_pkg_substr, find: "_", replace: "." );
	}
	else {
		if(IsMatchRegexp( inst_pkg_substr, "el[0-9]{1}_[0-9]{1}" ) && !IsMatchRegexp( fixed_pkg_substr, "el[0-9]{1}_[0-9]{1}" )){
			inst_pkg_substr = str_replace( string: inst_pkg_substr, find: "_", replace: "." );
		}
	}
	_inst_pkg = vuln_pkg + "~" + inst_pkg_substr;
	_fixed_pkg = vuln_pkg + "~" + fixed_pkg_substr;
	_inst_pkg_check = eregmatch( pattern: "^(.*)[.]([Ee][Ll][0-9]*)$", string: _inst_pkg );
	_fixed_pkg_check = eregmatch( pattern: "^(.*)[.]([Ee][Ll][0-9]*)$", string: _fixed_pkg );
	if(!isnull( _inst_pkg_check ) && !isnull( _fixed_pkg_check )){
		if(_inst_pkg_check[2] == _fixed_pkg_check[2]){
			_inst_pkg = _inst_pkg_check[1];
			_fixed_pkg = _fixed_pkg_check[1];
		}
	}
	if(eregmatch( pattern: "\\.[0-9]{1}\\.el[0-9]{1}", string: _inst_pkg ) && !eregmatch( pattern: "\\.[0-9]{1}\\.el[0-9]{1}", string: _fixed_pkg )){
		_fixed_pkg = ereg_replace( pattern: "(\\.el[0-9]{1})", replace: ".0\\1", string: _fixed_pkg );
	}
	norm_inst_pkg = "";
	for _comp in split( buffer: inst_pkg, sep: "~", keep: FALSE ) {
		norm_inst_pkg = NASLString( norm_inst_pkg, "-", _comp );
	}
	norm_inst_pkg = substr( norm_inst_pkg, 1 );
	norm_fixed_pkg = "";
	for _comp in split( buffer: fixed_pkg, sep: "~", keep: FALSE ) {
		norm_fixed_pkg = NASLString( norm_fixed_pkg, "-", _comp );
	}
	norm_fixed_pkg = substr( norm_fixed_pkg, 1 );
	ret_array["inst_pkg"] = _inst_pkg;
	ret_array["fixed_pkg"] = _fixed_pkg;
	ret_array["norm_inst_pkg"] = norm_inst_pkg;
	ret_array["norm_fixed_pkg"] = norm_fixed_pkg;
	return ret_array;
}
func isrpmvuln( pkg, rpm, rls ){
	var pkg, rpm, rls;
	var kbrls, rpms, pat, matches, pkg_name, _pkgs, report, report1, rpminfo;
	if(!pkg){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isrpmvuln#-#pkg" );
		return NULL;
	}
	if(!rpm){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isrpmvuln#-#rpm" );
		return NULL;
	}
	if(!rls){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isrpmvuln#-#rls" );
		return NULL;
	}
	kbrls = rpm_get_ssh_release();
	if(kbrls != rls){
		return NULL;
	}
	rpms = rpm_get_ssh_rpms();
	if(!rpms || rpms == ";"){
		return NULL;
	}
	pat = NASLString( "[\\n;](", pkg, "~[^;]+);" );
	matches = eregmatch( pattern: pat, string: rpms );
	if(!matches[1]){
		return NULL;
	}
	if(IsMatchRegexp( matches[1], "^kernel(-[0-9a-zA-Z_-]+)?~" )){
		pkg_name = split( buffer: rpms, sep: ";", keep: TRUE );
		for _pkgs in pkg_name {
			if(egrep( string: _pkgs, pattern: NASLString( "^", pkg, "~" ) )){
				matches = eregmatch( pattern: "^(" + pkg + "~[^;]+)", string: _pkgs );
				if(!matches[1]){
					continue;
				}
				rpminfo = rpmnorm( inst_pkg: matches[1], fixed_pkg: rpm, vuln_pkg: pkg );
				if(revcomp( a: rpminfo["inst_pkg"], b: rpminfo["fixed_pkg"] ) < 0){
					report = rpm_check_kernel_overwrite( vuln_pkg: pkg, inst_pkg: rpminfo["norm_inst_pkg"], fixed_pkg: rpminfo["norm_fixed_pkg"] );
					if(report){
						report1 += report;
					}
				}
			}
		}
		return report1;
	}
	rpminfo = rpmnorm( inst_pkg: matches[1], fixed_pkg: rpm, vuln_pkg: pkg );
	__pkg_match = TRUE;
	if(revcomp( a: rpminfo["inst_pkg"], b: rpminfo["fixed_pkg"] ) < 0){
		report = rpm_check_kernel_overwrite( vuln_pkg: pkg, inst_pkg: rpminfo["norm_inst_pkg"], fixed_pkg: rpminfo["norm_fixed_pkg"] );
		return report;
	}
	return NULL;
}

