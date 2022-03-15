func citrix_xenserver_check_report_is_vulnerable( version, hotfixes, patches ){
	var version, hotfixes, patches;
	var a, av, fixes, _patch;
	if(!version || !patches || !hotfixes){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version_patches_hotfixes#-#citrix_xenserver_check_report_is_vulnerable" );
		return;
	}
	if(!is_array( patches )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#patches_no_array#-#citrix_xenserver_check_report_is_vulnerable" );
		return;
	}
	a = eregmatch( pattern: "^([0-9]\\.[0-9]\\.[0-9])", string: version );
	if(isnull( a[1] )){
		return;
	}
	av = a[1];
	if(!is_array( patches[av] )){
		return;
	}
	if(ContainsString( hotfixes, "No hotfixes installed" )){
		citrix_xenserver_report_missing_patch( version: version, fix: patches[av] );
	}
	fixes = make_list();
	for _patch in patches[av] {
		if(( ContainsString( hotfixes, "ECC" ) && !ContainsString( _patch, "ECC" ) ) || ( ContainsString( _patch, "ECC" ) && !ContainsString( hotfixes, "ECC" ) )){
			continue;
		}
		if(!ContainsString( hotfixes, _patch )){
			fixes = make_list( fixes,
				 _patch );
		}
	}
	if(is_array( fixes )){
		citrix_xenserver_report_missing_patch( version: version, fix: fixes );
	}
	return;
}
func citrix_xenserver_report_missing_patch( version, fix ){
	var version, fix;
	var report;
	if(!version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version_#-#citrix_xenserver_report_missing_patch" );
	}
	if(!fix){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#fix#-#citrix_xenserver_report_missing_patch" );
	}
	report = "Installed version: " + version + "\n";
	report += "Missing hotfix:    " + join( list: fix, sep: " / " );
	security_message( port: 0, data: report );
	exit( 0 );
}

