func check_js_version( ver, fix ){
	if(!ver){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#ver#-#check_js_version" );
		return;
	}
	if(!fix){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#fix#-#check_js_version" );
		return;
	}
	ver = str_replace( string: ver, find: "-", replace: "." );
	fix = str_replace( string: fix, find: "-", replace: "." );
	if(!egrep( pattern: "^[0-9]+\\.[0-9]+((B|R|P)[0-9]+(\\.[0-9]+)?)?", string: ver )){
		return;
	}
	if(!egrep( pattern: "^[0-9]+\\.[0-9]+((B|R|P)[0-9]+(\\.[0-9]+)?)?", string: fix )){
		return;
	}
	if(ver == fix){
		return;
	}
	tver = ereg_replace( pattern: "(B|P|R)([0-9]+)", replace: ".\\2", string: ver );
	tfix = ereg_replace( pattern: "(B|P|R)([0-9]+)", replace: ".\\2", string: fix );
	if(tver == tfix){
		if(ContainsString( ver, "B" ) && ( ContainsString( fix, "R" ) || ContainsString( fix, "P" ) )){
			return TRUE;
		}
		if(ContainsString( ver, "R" ) && ContainsString( fix, "P" )){
			return TRUE;
		}
		return;
	}
	v_build = 0;
	f_build = 0;
	ver_array = split( buffer: tver, sep: ".", keep: FALSE );
	v_major = ver_array[0];
	v_minor = ver_array[1];
	v_rev = ver_array[2];
	if(!isnull( ver_array[3] )){
		v_build = ver_array[3];
	}
	fix_array = split( buffer: tfix, sep: ".", keep: FALSE );
	f_major = fix_array[0];
	f_minor = fix_array[1];
	f_rev = fix_array[2];
	if(!isnull( fix_array[3] )){
		f_build = fix_array[3];
	}
	if(v_major < f_major){
		return TRUE;
	}
	if(v_major > f_major){
		return;
	}
	if(v_minor < f_minor){
		return TRUE;
	}
	if(v_minor > f_minor){
		return;
	}
	if(v_rev < f_rev){
		return TRUE;
	}
	if(v_rev > f_rev){
		return;
	}
	if(v_build < f_build){
		return TRUE;
	}
	if(v_build > f_build){
		return;
	}
	return;
}

