var __ssh_solosversion;
func get_ssh_solosversion(  ){
	var solosvers;
	if( !isnull( __ssh_solosversion ) ){
		solosvers = NASLString( __ssh_solosversion );
	}
	else {
		solosvers = NASLString( get_kb_item( "ssh/login/solosversion" ) );
		__ssh_solosversion = solosvers;
	}
	return solosvers;
}
func patch_installed( showrev, patch ){
	var v, p, _r, patches, spatches;
	v = split( buffer: patch, sep: "-", keep: FALSE );
	patches = egrep( pattern: "^Patch: " + v[0], string: showrev );
	if(!patches){
		return 0;
	}
	spatches = split( buffer: patches, keep: FALSE );
	for _r in spatches {
		_r = ereg_replace( pattern: "Patch: ([0-9]*-[0-9]*) .*", replace: "\\1", string: _r );
		p = split( buffer: _r, sep: "-", keep: FALSE );
		if(int( p[1] ) >= int( v[1] )){
			return 1;
		}
	}
	return 0;
}
func solaris_check_patch( release, arch, patch, package, obsoleted_by ){
	var showrev, r, flag, packages, _p;
	if(ContainsString( release, "_x86" )){
		release -= "_x86";
	}
	kb_release = get_ssh_solosversion() - "\n";
	kb_arch = get_kb_item( "ssh/login/solhardwaretype" ) - "\n";
	if(kb_release != release || kb_arch != arch){
		return 0;
	}
	packages = get_kb_item( "ssh/login/solpackages" );
	showrev = get_kb_item( "ssh/login/solpatches" );
	if(!packages || !showrev || !release || !patch){
		return 0;
	}
	flag = 0;
	if( strlen( package ) ){
		package = split( buffer: package, sep: " ", keep: FALSE );
		for _p in package {
			if(egrep( pattern: _p, string: packages )){
				flag++;
			}
		}
	}
	else {
		flag = 1;
	}
	if(flag == 0){
		return 0;
	}
	if(patch_installed( patch: patch, showrev: showrev )){
		return 1;
	}
	if(obsoleted_by && patch_installed( patch: obsoleted_by, showrev: showrev )){
		return 1;
	}
	return -1;
}

