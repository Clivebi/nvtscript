var __kb_smb_ver, __kb_host_cpe;
func policy_logging( text, error ){
	var text, error;
	var verbose;
	verbose = get_kb_item( "Compliance/verbose" );
	if(verbose){
		if( error ){
			log_message( data: text, port: 0, proto: "Policy/Control/Error" );
		}
		else {
			log_message( data: text, port: 0, proto: "Policy/Control" );
		}
	}
}
func policy_add_oid(  ){
	set_kb_item( name: "PolicyOIDs", value: get_script_oid() );
}
func policy_set_compliance( compliant ){
	var compliant;
	set_kb_item( name: get_script_oid() + "/COMPLIANT", value: NASLString( compliant ) );
}
func policy_set_kb( val ){
	var val;
	set_kb_item( name: get_script_oid() + "/RESULT", value: chomp( NASLString( val ) ) );
}
func policy_set_kb_hcu( id, val ){
	var id, val;
	set_kb_item( name: get_script_oid() + "/RESULT/" + id, value: chomp( NASLString( val ) ) );
}
func policy_set_dval( dval ){
	var dval;
	set_kb_item( name: get_script_oid() + "/DEFAULT", value: chomp( NASLString( dval ) ) );
}
func policy_fixtext( fixtext ){
	var fixtext;
	set_kb_item( name: get_script_oid() + "/FIX", value: fixtext );
}
func policy_control_name( title ){
	var title;
	title = str_replace( string: title, find: "\n", replace: " " );
	set_kb_item( name: get_script_oid() + "/NAME", value: title );
}
func policy_testtype( type, cmd ){
	var type, cmd;
	if(!cmd){
		cmd = "None";
	}
	if(!type){
		type = "None";
	}
	set_kb_item( name: get_script_oid() + "/TEST_TYPE", value: type );
	set_kb_item( name: get_script_oid() + "/CMD", value: cmd );
}
func policy_logging_registry( type, key, item, value ){
	var type, key, item, value;
	policy_logging( text: "Registry value " + type + "\\" + key + "!" + item + " is set to: " + value );
}
func policy_reporting( result, default, compliant, fixtext, type, test, info ){
	var result, default, compliant, fixtext, type, test, info;
	var report;
	if(!NASLString( result )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_reporting#-#result" );
		result = "Unknown";
	}
	if(!NASLString( default )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_reporting#-#default" );
		default = "Unknown";
	}
	if(!compliant){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_reporting#-#compliant" );
		compliant = "Incomplete";
	}
	if(!fixtext){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_reporting#-#fixtext" );
		fixtext = "Unknown";
	}
	if(!type){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_reporting#-#type" );
		type = "Unknown";
	}
	if(!test){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_reporting#-#test" );
		test = "Unknown";
	}
	if( info ){
		set_kb_item( name: get_script_oid() + "/NOTE", value: info );
		report = policy_build_report( result: result, default: default, compliant: compliant, fixtext: fixtext, type: type, test: test, info: info );
	}
	else {
		report = policy_build_report( result: result, default: default, compliant: compliant, fixtext: fixtext, type: type, test: test );
	}
	policy_logging( text: report );
}
func policy_rsop_query( query, default, min, max ){
	var query, default, min, max;
	var infos, ret, handle, res, splitRes;
	if(IsMatchRegexp( query, "SecuritySettingBoolean" )){
		if(min){
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_rsop_query: 'query' contains SecuritySettingBoolean and 'min' is set to TRUE which is not compatible." );
		}
		if(max){
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_rsop_query: 'query' contains SecuritySettingBoolean and 'max' is set to TRUE which is not compatible." );
		}
	}
	if(!query){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_rsop_query#-#query" );
	}
	if(isnull( default )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_rsop_query#-#default" );
	}
	infos = kb_smb_wmi_connectinfo();
	if(!infos){
		ret["value"] = "Error";
		ret["compliant"] = "incomplete";
		ret["comment"] = "No authentication possible.";
		return ( ret );
	}
	handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"], ns: "root\\rsop\\computer" );
	if(!handle){
		ret["value"] = "Error";
		ret["compliant"] = "incomplete";
		ret["comment"] = "No WMI connection possible.";
		return ( ret );
	}
	res = wmi_query_rsop( wmi_handle: handle, query: query );
	wmi_close( wmi_handle: handle );
	if(!res){
		if( tolower( default ) == "none" ) {
			ret["compliant"] = "yes";
		}
		else {
			ret["compliant"] = "no";
		}
		ret["value"] = "None";
		ret["comment"] = "No setting found for this query.";
		return ( ret );
	}
	splitRes = split( buffer: res, sep: "|", keep: FALSE );
	if( max_index( splitRes ) < 4 ) {
		ret["value"] = "None";
	}
	else {
		ret["value"] = chomp( splitRes[4] );
	}
	if( default == ret["value"] ) {
		ret["compliant"] = "yes";
	}
	else {
		if( min && int( ret["value"] ) >= int( default ) ) {
			ret["compliant"] = "yes";
		}
		else {
			if( max && int( ret["value"] ) <= int( default ) ) {
				ret["compliant"] = "yes";
			}
			else {
				ret["compliant"] = "no";
			}
		}
	}
	return ( ret );
}
func rsop_userprivilegeright( select, keyname ){
	var select, keyname;
	var infos, handle, query, res, splitRes, accountList, MaxIndexAccountList, i, returnValue;
	infos = kb_smb_wmi_connectinfo();
	if(!infos){
		return;
	}
	handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"], ns: "root\\rsop\\computer" );
	if(!handle){
		return;
	}
	query = "SELECT " + select + " FROM RSOP_UserPrivilegeRight WHERE UserRight = '" + keyname + "'";
	res = wmi_query_rsop( wmi_handle: handle, query: query );
	wmi_close( wmi_handle: handle );
	res = chomp( res );
	if(!res){
		return "None";
	}
	splitRes = split( buffer: res, keep: FALSE );
	accountList = split( buffer: splitRes[1], sep: "|", keep: FALSE );
	MaxIndexAccountList = max_index( accountList );
	for(i = 0;i < MaxIndexAccountList - 2;i++){
		returnValue += ", " + accountList[i];
	}
	returnValue = str_replace( string: returnValue, find: ", ", replace: "", count: 1 );
	return ( returnValue );
}
func policy_rsop_match( select, keyname, default ){
	var select, keyname, default, ret, user_list, _user, default_list, user_list_split;
	if(!( user_list = rsop_userprivilegeright( select: select, keyname: keyname ) )){
		ret["compliant"] = "incomplete";
		ret["value"] = "None";
		ret["comment"] = "No WMI query possible";
		return ( ret );
	}
	if( user_list == "None" && default == "None" ){
		ret["compliant"] = "yes";
		ret["value"] = "None";
		ret["comment"] = "No account found for this setting";
		return ( ret );
	}
	else {
		if(user_list == "None"){
			ret["compliant"] = "no";
			ret["value"] = "None";
			ret["comment"] = "No account found for this setting";
			return ( ret );
		}
	}
	ret["compliant"] = "yes";
	ret["comment"] = "";
	ret["value"] = user_list;
	user_list_split = split( buffer: user_list, sep: ",", keep: FALSE );
	for _user in user_list_split {
		_user = ereg_replace( string: chomp( _user ), pattern: "^\\s+", replace: "" );
		if(ContainsString( default, _user )){
			continue;
		}
		ret["compliant"] = "no";
	}
	default_list = split( buffer: default, sep: ",", keep: FALSE );
	for _user in default_list {
		_user = ereg_replace( string: chomp( _user ), pattern: "^\\s+", replace: "" );
		if(ContainsString( user_list, _user )){
			continue;
		}
		ret["compliant"] = "no";
	}
	return ( ret );
}
func win32_useraccount( select, name ){
	var select, name;
	var infos, handle, query, res;
	infos = kb_smb_wmi_connectinfo();
	if(!infos){
		exit( 0 );
	}
	handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
	if(!handle){
		policy_logging( text: "WMI Connect to host failed." );
		policy_set_kb( val: "error" );
		exit( 0 );
	}
	query = "SELECT " + select + " FROM Win32_UserAccount WHERE Name = '" + name + "'";
	res = wmi_query( wmi_handle: handle, query: query );
	wmi_close( wmi_handle: handle );
	return ( res );
}
func get_package_version( package, partial_match ){
	var package, partial_match;
	var packages_string, packages_list, _pak, packages_split, name, version, _line, line_split;
	if(!package){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#package_version#-#package" );
		return;
	}
	if( packages_string = get_kb_item( "ssh/login/rpms" ) ){
		packages_list = split( buffer: packages_string, sep: ";", keep: FALSE );
		for _pak in packages_list {
			package_split = split( buffer: _pak, sep: "~", keep: FALSE );
			name = package_split[0];
			version = package_split[1];
			if( partial_match ){
				if(ContainsString( name, package )){
					return version;
				}
			}
			else {
				if(name == package){
					return version;
				}
			}
		}
	}
	else {
		if(packages_string = get_kb_item( "ssh/login/packages" )){
			packages_list = split( buffer: packages_string, keep: FALSE );
			for _line in packages_list {
				if(IsMatchRegexp( _line, "^ii" )){
					line_split = ereg_replace( string: _line, pattern: "\\s+", replace: "|" );
					packages_info = split( buffer: line_split, sep: "|", keep: FALSE );
					name = packages_info[1];
					version = packages_info[2];
					if( partial_match ){
						if(ContainsString( name, package )){
							return version;
						}
					}
					else {
						if(name == package){
							return version;
						}
					}
				}
			}
		}
	}
	return;
}
func get_grub_config_file(  ){
	var grub_config_files, grub_config_dirs, _dir, _file, config_file;
	grub_config_files = make_list( "grub.conf",
		 "grub.cfg",
		 "menu.lst" );
	grub_config_dirs = make_list( "/boot/grub/",
		 "/boot/grub2/" );
	for _dir in grub_config_dirs {
		for _file in grub_config_files {
			config_file = ssh_find_file( file_name: _dir + _file );
			if(config_file){
				return config_file[0];
			}
		}
	}
	return;
}
func ssh_cmd_without_errors( socket, cmd ){
	var socket, cmd;
	var ret;
	ret = ssh_cmd( socket: socket, cmd: cmd, return_errors: FALSE );
	if(ContainsString( ret, "No such file or directory" ) || ContainsString( ret, "command not found" ) || ContainsString( ret, "esxcli: error" )){
		return;
	}
	return ( ret );
}
func linux_file_permissions( file, socket ){
	var file, socket;
	var stat_cmd, stat, return_array;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#linux_file_permissions#-#socket" );
		return;
	}
	if(!file){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#linux_file_permissions#-#file" );
		return;
	}
	stat_cmd = "stat " + file;
	stat = ssh_cmd_without_errors( socket: socket, cmd: stat_cmd );
	if(stat && ( !ContainsString( tolower( stat ), "permission denied" ) )){
		return_array = make_list();
		return_array["gid"] = policy_chown_get_gid( stat: stat );
		return_array["uid"] = policy_chown_get_uid( stat: stat );
		return_array["permissions"] = policy_get_access_permissions( stat: stat );
		return ( return_array );
	}
	return;
}
func linux_service_is_enabled( service, socket ){
	var service, socket;
	var systemctl_cmd, systemctl, chkconfig_cmd, chkconfig, ls_grep_cmd, ls_grep, enabled;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#linux_file_permissions#-#socket" );
		return;
	}
	if(!service){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#linux_file_permissions#-#service" );
		return;
	}
	systemctl_cmd = "systemctl is-enabled " + service;
	systemctl = ssh_cmd_without_errors( socket: socket, cmd: systemctl_cmd );
	if(ContainsString( systemctl, "enabled" )){
		return TRUE;
	}
	chkconfig_cmd = "chkconfig --list " + service;
	chkconfig = ssh_cmd_without_errors( socket: socket, cmd: chkconfig_cmd );
	if(ContainsString( chkconfig, "2:on" ) && ContainsString( chkconfig, "3:on" ) && ContainsString( chkconfig, "4:on" ) && ContainsString( chkconfig, "5:on" )){
		return TRUE;
	}
	ls_grep_cmd = "ls /etc/rc*.d | grep " + service;
	ls_grep = ssh_cmd_without_errors( socket: socket, cmd: ls_grep_cmd );
	enabled = eregmatch( string: ls_grep, pattern: "[\\^S][^\n\r]*" );
	if(enabled){
		return TRUE;
	}
	return;
}
func check_permission_denied( value, file ){
	var value, file;
	var ret;
	if(ContainsString( tolower( value ), "permission denied" )){
		ret = "No permission to read in file \"" + file + "\".";
		return ( ret );
	}
	return;
}
func policy_verify_win_ver( min_ver ){
	var min_ver, cur_ver;
	if(min_ver && !IsMatchRegexp( min_ver, "^[0-9.]+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_verify_win_ver: wrong syntax in 'min_ver', passed: " + min_ver + ", expected e.g. 6{.2}" );
		return NULL;
	}
	cur_ver = get_kb_item( "SMB/WindowsVersion" );
	if(!cur_ver){
		return FALSE;
	}
	if(cur_ver && !IsMatchRegexp( cur_ver, "^[0-9.]+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_verify_win_ver: wrong syntax in 'cur_ver', extracted: " + cur_ver + ", expected e.g. 6{.2}" );
		return NULL;
	}
	if(!min_ver && cur_ver){
		return TRUE;
	}
	if(version_is_greater_equal( version: cur_ver, test_version: min_ver )){
		return TRUE;
	}
	return FALSE;
}
func policy_report_wrong_os( target_os ){
	var target_os, ret;
	ret["value"] = "None";
	ret["comment"] = "Host does not run " + target_os + ".";
	ret["compliant"] = "incomplete";
	return ret;
}
func policy_match_exact_reg_dword( key, item, type, default ){
	var key, item, type, default;
	var value, comment, compliant, ret;
	value = registry_get_dword( key: key, item: item, type: type );
	value = chomp( value );
	if( value == "" ){
		comment = "Registry key not found.";
		compliant = "incomplete";
		value = "None";
	}
	else {
		if( isnull( default ) || default == "" ){
			compliant = "incomplete";
		}
		else {
			if( int( value ) == int( default ) ){
				compliant = "yes";
			}
			else {
				compliant = "no";
			}
		}
	}
	ret["value"] = value;
	ret["compliant"] = compliant;
	if( comment ){
		ret["comment"] = comment;
	}
	else {
		ret["comment"] = "";
	}
	return ret;
}
func policy_match_reg_sz( key, item, type, default, partial, multi_sz ){
	var key, item, type, default, partial, multi_sz;
	var value, comment, compliant, ret, lower_value, lower_default;
	if( multi_sz ){
		value = registry_get_sz( key: key, item: item, type: type, multi_sz: TRUE );
		if(value){
			value = str_replace( string: value, find: "\n", replace: "," );
		}
	}
	else {
		value = registry_get_sz( key: key, item: item, type: type );
	}
	value = chomp( value );
	if( !value || isnull( value ) ){
		value = "Unknown";
		compliant = "incomplete";
	}
	else {
		lower_value = tolower( NASLString( value ) );
		lower_default = tolower( NASLString( default ) );
		if( partial && ContainsString( lower_value, lower_default ) ){
			compliant = "yes";
		}
		else {
			if( lower_value == lower_default ){
				compliant = "yes";
			}
			else {
				compliant = "no";
			}
		}
	}
	ret["value"] = value;
	ret["compliant"] = compliant;
	if( comment ){
		ret["comment"] = comment;
	}
	else {
		ret["comment"] = "";
	}
	return ret;
}
func policy_set_kbs( type, cmd, default, solution, title, value, compliant ){
	var type, cmd, default, solution, title, value, compliant;
	if(!type){
		type = "Unknown";
	}
	if(!cmd){
		cmd = "Unknown";
	}
	if(!default){
		default = "Unknown";
	}
	if(!solution){
		solution = "Unknown";
	}
	if(!title){
		title = "Unknown";
	}
	if(!value){
		value = "Unknown";
	}
	if(!compliant){
		compliant = "incomplete";
	}
	policy_testtype( type: type, cmd: cmd );
	policy_add_oid();
	policy_set_dval( dval: default );
	policy_fixtext( fixtext: solution );
	policy_control_name( title: title );
	policy_set_kb( val: value );
	policy_set_compliance( compliant: compliant );
}
func policy_check_linux_ssh_shell(  ){
	if(!get_kb_item( "login/SSH/success" ) || get_kb_item( "ssh/no_linux_shell" ) || get_kb_item( "ssh/restricted_shell" )){
		return ( FALSE );
	}
	return ( TRUE );
}
func policy_report_empty_hku(  ){
	var ret;
	ret["value"] = "None";
	ret["comment"] = "No valid SIDs found in HKU.";
	ret["compliant"] = "incomplete";
	return ret;
}
func policy_match_exact_dword_profiles( key, item, default, sids ){
	var key, item, default, sids;
	var incomplete_sids, fail_sids, ret, _sid;
	incomplete_sids = "";
	fail_sids = "";
	ret["compliant"] = "yes";
	ret["value"] = default;
	ret["comment"] = "";
	for _sid in sids {
		if(!IsMatchRegexp( _sid, "^S-1-5-[0-9,-]+$" ) || IsMatchRegexp( _sid, "^S-1-5-(18|19|20)" )){
			continue;
		}
		key = strcat( _sid, "\\", key );
		value = registry_get_dword( key: key, item: item, type: "HKU" );
		value = chomp( value );
		if( !value ){
			incomplete_sids += ", " + _sid;
		}
		else {
			if(int( value ) != int( default )){
				fail_sids += ", " + _sid;
			}
		}
	}
	if(incomplete_sids != ""){
		ret["compliant"] = "incomplete";
		ret["value"] = "None";
		ret["comment"] = "Registry key not found for SIDs: " + str_replace( string: incomplete_sids, find: ", ", replace: "", count: 1 );
	}
	if(fail_sids != ""){
		ret["compliant"] = "no";
		ret["value"] = "None";
		if(ret["comment"] != ""){
			ret["comment"] += "\n              ";
		}
		ret["comment"] += "Non compliant SIDs: " + str_replace( string: fail_sids, find: ", ", replace: "", count: 1 );
	}
	return ( ret );
}
func policy_host_runs_windows_10(  ){
	var win_ver, host_cpe;
	if( !isnull( __kb_smb_ver ) ){
		win_ver = NASLString( __kb_smb_ver );
	}
	else {
		win_ver = NASLString( get_kb_item( "SMB/WindowsVersion" ) );
		if( strlen( win_ver ) > 0 ){
			__kb_smb_ver = win_ver;
		}
		else {
			return ( FALSE );
		}
	}
	if( !isnull( __kb_host_cpe ) ){
		host_cpe = NASLString( __kb_host_cpe );
	}
	else {
		host_cpe = os_get_best_cpe();
		if( strlen( host_cpe ) > 0 ){
			__kb_host_cpe = host_cpe;
		}
		else {
			return ( FALSE );
		}
	}
	if(win_ver && ( IsMatchRegexp( host_cpe, "microsoft:windows_10" ) )){
		return ( TRUE );
	}
	return ( FALSE );
}
func policy_wmi_access(  ){
	if(!get_kb_item( "WMI/access_successful" )){
		return ( FALSE );
	}
	return ( TRUE );
}
func policy_report_no_wmi_access(  ){
	var ret;
	ret["value"] = "None";
	ret["comment"] = "No WMI access to the host possible.";
	ret["compliant"] = "incomplete";
	return ( ret );
}
func policy_min_max_reg_dword( key, item, type, default, min, max, not_zero, as_sz ){
	var key, item, type, default, min, max, not_zero, as_sz;
	var value, comment, compliant, ret;
	if(!min && !max){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_min_max_reg_dword#-#min_max" );
	}
	if( as_sz ) {
		value = registry_get_sz( key: key, item: item, type: type );
	}
	else {
		value = registry_get_dword( key: key, item: item, type: type );
	}
	value = chomp( value );
	if( value == "" ){
		comment = "Registry key not found.";
	}
	else {
		if(min){
			if( int( value ) >= int( default ) ) {
				compliant = "yes";
			}
			else {
				compliant = "no";
			}
		}
		if(max){
			if( int( value ) <= int( default ) ){
				if( not_zero && int( value ) == 0 ) {
					compliant = "no";
				}
				else {
					compliant = "yes";
				}
			}
			else {
				compliant = "no";
			}
		}
	}
	if( !value ) {
		ret["value"] = "None";
	}
	else {
		ret["value"] = value;
	}
	if( !compliant ) {
		ret["compliant"] = "incomplete";
	}
	else {
		ret["compliant"] = compliant;
	}
	if( !comment ) {
		ret["comment"] = "";
	}
	else {
		ret["comment"] = comment;
	}
	return ret;
}
func policy_wmi_query( query ){
	var query, infos, handle, res;
	if(!NASLString( query )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_wmi_query#-#query" );
		return ( FALSE );
	}
	infos = kb_smb_wmi_connectinfo();
	if(!infos){
		return ( FALSE );
	}
	handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
	if(!handle){
		return ( FALSE );
	}
	res = wmi_query( wmi_handle: handle, query: query );
	wmi_close( wmi_handle: handle );
	if(!res || ContainsString( res, "NTSTATUS" )){
		return ( FALSE );
	}
	return ( res );
}
func policy_powershell_cmd( cmd ){
	var cmd;
	var infos, result;
	if(defined_func( "win_cmd_exec" )){
		infos = kb_smb_wmi_connectinfo();
		if(!infos){
			return;
		}
		cmd = "powershell -Command \" & {" + cmd + "}\"";
		result = win_cmd_exec( cmd: cmd, password: infos["password"], username: infos["username_wincmd"] );
		result = chomp( result );
		if(!result){
			return;
		}
		if(IsMatchRegexp( result, "fullyqualifiederrorid\\s*:\\s*[a-zA-Z]+" ) || IsMatchRegexp( result, "categoryinfo\\s*:\\s*[a-zA-Z]+" )){
			return;
		}
		result = ereg_replace( string: result, pattern: "(Impacket .+ dialect used)", replace: "" );
		result = ereg_replace( string: chomp( result ), pattern: "^\\s+", replace: "" );
		if(result){
			return ( result );
		}
	}
	return;
}
func policy_report_no_powershell_result(  ){
	var ret;
	ret["value"] = "None";
	ret["comment"] = "The powershell command did not return any result. Reasons: Command does not exist, powershell.exe access was denied";
	ret["compliant"] = "incomplete";
	return ( ret );
}
func policy_report_powershell_result( value ){
	var ret, value;
	ret["value"] = value;
	ret["comment"] = "This script only shows the output of the powershell command.";
	ret["compliant"] = "yes";
	return ( ret );
}
func policy_win_get_advanced_audit_results( key, default ){
	var ret, key, default, value;
	value = get_kb_item( key );
	if( !value ){
		ret["value"] = "None";
		ret["compliant"] = "incomplete";
		ret["comment"] = "Can not determine audit status";
	}
	else {
		ret["value"] = value;
		if( ContainsString( value, default ) ) {
			ret["compliant"] = "yes";
		}
		else {
			ret["compliant"] = "no";
		}
	}
	return ( ret );
}
func policy_match_multiple_reg_values( key, type, item_default_array, reg_sz, reg_dword ){
	var key, type, item_default_array, reg_sz, reg_dword;
	var compliant, _item, default, value, comment, total_value, ret;
	if(!item_default_array || !key || !type){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_match_multiple_reg_values#-#VALUES" );
		return;
	}
	compliant = "yes";
	for _item in keys( item_default_array ) {
		default = item_default_array[_item];
		if( reg_sz ) {
			value = registry_get_sz( key: key, item: _item, type: type );
		}
		else {
			value = registry_get_dword( key: key, item: _item, type: type );
		}
		value = chomp( value );
		if( value == "" ){
			comment += ", Registry key not found: " + _item;
			if(compliant != "no"){
				compliant = "incomplete";
			}
			total_value += ", " + _item + ": None";
		}
		else {
			if(value != default){
				compliant = "no";
			}
			total_value += ", " + _item + ": " + value;
		}
	}
	ret["value"] = str_replace( string: total_value, find: ", ", replace: "", count: 1 );
	ret["compliant"] = compliant;
	if( comment ) {
		ret["comment"] = str_replace( string: comment, find: ", ", replace: "", count: 1 );
	}
	else {
		ret["comment"] = "";
	}
	return ret;
}
func policy_get_major_version_app( str, sep, count, glue ){
	var str, sep, count, glue, split_version, counter, major_version;
	split_version = split( buffer: str, sep: sep, keep: FALSE );
	for(counter = 0;counter < count;counter++){
		if( counter == 0 ) {
			major_version = NASLString( split_version[counter] );
		}
		else {
			major_version = NASLString( major_version, glue, split_version[counter] );
		}
	}
	return ( major_version );
}
func policy_report_wrong_app( target_app ){
	var target_app, ret;
	ret["value"] = "None";
	ret["comment"] = "No installation found for software: " + target_app + ".";
	ret["compliant"] = "incomplete";
	return ret;
}
func policy_build_list_from_string( str ){
	var str, app_list, counter;
	app_list = split( buffer: str, sep: ",", keep: "FALSE" );
	for(counter = 0;counter < max_index( app_list );counter++){
		app_list[counter] = ereg_replace( string: chomp( app_list[counter] ), pattern: "^(\\s+)", replace: "" );
	}
	return ( app_list );
}
func policy_build_items_default_list( list, default ){
	var list, default, _item, ret;
	for _item in list {
		ret[_item] = default;
	}
	return ( ret );
}
func policy_microsoft_windows_target_string(  ){
	return ( "Microsoft Windows" );
}
func policy_build_report( result, default, compliant, fixtext, type, test, info ){
	var result, default, compliant, fixtext, type, test, info;
	var report;
	report += "Compliant:    " + toupper( compliant ) + "\n";
	report += "Actual Value: " + result + "\n";
	report += "Set Point:    " + default + "\n";
	report += "Type of Test: " + type + "\n";
	report += "Test:         " + test + "\n";
	report += "Solution:     " + fixtext;
	if(info){
		report += "\n" + "Notes:        " + info;
	}
	return ( report );
}
func policy_setting_exact_match( value, set_point ){
	var value, set_point;
	if(!value || !set_point){
		return ( "incomplete" );
	}
	if( value == set_point ) {
		return ( "yes" );
	}
	else {
		return ( "no" );
	}
}
func policy_setting_min_match( value, set_point ){
	var value, set_point;
	if(!value || !set_point){
		return ( "incomplete" );
	}
	if(value == set_point){
		return ( "yes" );
	}
	if(!IsMatchRegexp( value, "[0-9]+" ) || !IsMatchRegexp( set_point, "[0-9]+" )){
		return ( "no" );
	}
	value = ereg_replace( string: chomp( value ), pattern: "^(\\s+)", replace: "" );
	set_point = ereg_replace( string: chomp( set_point ), pattern: "^(\\s+)", replace: "" );
	if( int( value ) >= int( set_point ) ) {
		return ( "yes" );
	}
	else {
		return ( "no" );
	}
}
func policy_setting_max_match( value, set_point, non_zero ){
	var value, set_point, non_zero;
	if(!value || !set_point){
		return ( "incomplete" );
	}
	if( value == set_point ){
		return ( "yes" );
	}
	else {
		if(non_zero && value == "0"){
			return ( "no" );
		}
	}
	if(!IsMatchRegexp( value, "[0-9]+" ) || !IsMatchRegexp( set_point, "[0-9]+" )){
		return ( "no" );
	}
	value = ereg_replace( string: chomp( value ), pattern: "^(\\s+)", replace: "" );
	set_point = ereg_replace( string: chomp( set_point ), pattern: "^(\\s+)", replace: "" );
	if( int( value ) <= int( set_point ) ) {
		return ( "yes" );
	}
	else {
		return ( "no" );
	}
}
func policy_setting_in_range( value, min, max ){
	var value, min, max;
	if(!value || !min || !max){
		return ( "incomplete" );
	}
	if(!IsMatchRegexp( value, "[0-9]+" ) || !IsMatchRegexp( min, "[0-9]+" ) || !IsMatchRegexp( max, "[0-9]+" )){
		return ( "no" );
	}
	value = ereg_replace( string: chomp( value ), pattern: "^(\\s+)", replace: "" );
	min = ereg_replace( string: chomp( min ), pattern: "^(\\s+)", replace: "" );
	max = ereg_replace( string: chomp( max ), pattern: "^(\\s+)", replace: "" );
	if( int( value ) >= int( min ) && int( value ) <= int( max ) ) {
		return ( "yes" );
	}
	else {
		return ( "no" );
	}
}
func policy_settings_list_in_value( value, set_points, sep ){
	var value, set_points, sep, compliant, default_list, _setting;
	if(!value || !set_points){
		return ( "incomplete" );
	}
	compliant = "yes";
	default_list = split( buffer: set_points, sep: sep, keep: FALSE );
	for _setting in default_list {
		_setting = ereg_replace( string: chomp( _setting ), pattern: "^\\s+", replace: "" );
		if(!ContainsString( value, _setting )){
			compliant = "no";
		}
	}
	return ( compliant );
}
func policy_settings_lists_match( value, set_points, sep ){
	var value, set_points, sep;
	var compliant, default_list, _setting, value_list;
	default_list = split( buffer: set_points, sep: sep, keep: FALSE );
	for _setting in default_list {
		_setting = ereg_replace( string: chomp( _setting ), pattern: "^\\s+", replace: "" );
		if(!ContainsString( value, _setting )){
			return ( "no" );
		}
	}
	value_list = split( buffer: value, sep: sep, keep: FALSE );
	for _setting in value_list {
		_setting = ereg_replace( string: chomp( _setting ), pattern: "^\\s+", replace: "" );
		if(!ContainsString( set_points, _setting )){
			return ( "no" );
		}
	}
	return ( "yes" );
}
func policy_chown_get_uid( stat ){
	var stat;
	var uid;
	uid = eregmatch( string: stat, pattern: "Uid: \\(\\s+[0-9]+/\\s+([^)]+)\\)" );
	if(!uid){
		return;
	}
	return ( uid[1] );
}
func policy_chown_get_gid( stat ){
	var stat;
	var gid;
	gid = eregmatch( string: stat, pattern: "Gid: \\(\\s+[0-9]+/\\s+([^)]+)\\)" );
	if(!gid){
		return;
	}
	return ( gid[1] );
}
func policy_get_access_permissions( stat ){
	var stat;
	var perm;
	if(!stat){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_get_access_permissions: stat empty" );
		return;
	}
	perm = eregmatch( string: stat, pattern: "Access: \\([0-9]([0-9]{3})" );
	if(!perm){
		return;
	}
	return ( perm[1] );
}
func policy_access_permissions_match_or_stricter( value, set_point ){
	var value, set_point;
	var octal_to_filemode, value_filemode, set_point_filemode, compliant, sticky_bit_value, sticky_bit_set_point, i;
	if(!value || !set_point){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_access_permissions_match_or_stricter: value or set_point empty" );
		return;
	}
	value = NASLString( value );
	set_point = NASLString( set_point );
	octal_to_filemode = make_array( "0", "---", "1", "--x", "2", "-w-", "3", "-wx", "4", "r--", "5", "r-x", "6", "rw-", "7", "rwx" );
	value_filemode = "";
	set_point_filemode = "";
	compliant = "yes";
	if(strlen( value ) == 4){
		sticky_bit_value = value[0];
		value = substr( value, 1 );
	}
	if(strlen( set_point ) == 4){
		sticky_bit_set_point = set_point[0];
		set_point = substr( set_point, 1 );
		if(sticky_bit_value != sticky_bit_set_point){
			compliant = "no";
		}
	}
	for(i = 0;i < 3;i++){
		value_filemode += octal_to_filemode[value[i]];
		set_point_filemode += octal_to_filemode[set_point[i]];
	}
	for(i = 0;i < 9;i++){
		if(set_point_filemode[i] == value_filemode[i] || value_filemode[i] == "-"){
			continue;
		}
		compliant = "no";
	}
	return ( compliant );
}
func policy_build_string_from_list( list, sep ){
	var list, sep;
	var ret_string, _item;
	ret_string = "";
	for _item in list {
		ret_string += sep + _item;
	}
	ret_string = str_replace( string: ret_string, find: sep, replace: "", count: 1 );
	return ( ret_string );
}
func policy_linux_stat_file( socket, file, kb_name ){
	var socket, file, kb_name, cmd, stat;
	cmd = "stat " + file + " 2>/dev/null";
	stat = ssh_cmd_without_errors( socket: socket, cmd: cmd );
	if(!kb_name){
		kb_name = file;
	}
	if( !stat ) {
		set_kb_item( name: "Policy/linux/" + kb_name + "/stat/ERROR", value: TRUE );
	}
	else {
		set_kb_item( name: "Policy/linux/" + kb_name + "/stat", value: stat );
	}
}
func policy_linux_file_content( socket, file ){
	var socket, file, cmd, content;
	cmd = "cat " + file + " 2>/dev/null";
	content = ssh_cmd_without_errors( socket: socket, cmd: cmd );
	if( !content ) {
		set_kb_item( name: "Policy/linux/" + file + "/content/ERROR", value: TRUE );
	}
	else {
		set_kb_item( name: "Policy/linux/" + file + "/content", value: content );
	}
}
func policy_return_greater_value( value1, value2 ){
	var value1, value2;
	if(!value1 && !value2){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_return_greater_value: value1 and value2 empty" );
		return;
	}
	if(!value1){
		return ( value2 );
	}
	if(!value2){
		return ( value1 );
	}
	if(int( value1 ) > int( value2 )){
		return ( value1 );
	}
	return ( value2 );
}
func policy_return_smaller_value( value1, value2 ){
	var value1, value2;
	if(!value1 && !value2){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_return_smaller_value: value1 and value2 empty" );
		return;
	}
	if(!value1){
		return ( value2 );
	}
	if(!value2){
		return ( value1 );
	}
	if(int( value1 ) < int( value2 )){
		return ( value1 );
	}
	return ( value2 );
}
func policy_read_files_in_directory( socket, directory ){
	var socket, directory, files, _file;
	if(!directory || !socket){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_read_files_in_directory: directory or socket empty" );
	}
	files = ssh_cmd_without_errors( socket: socket, cmd: "ls --format=single-column " + directory );
	if( !files ){
		set_kb_item( name: "Policy/linux/" + directory + "/ERROR", value: TRUE );
	}
	else {
		for _file in split( buffer: files, keep: FALSE ) {
			set_kb_item( name: "Policy/linux/" + directory + "/files/", value: directory + _file );
			policy_linux_stat_file( socket: socket, file: directory + _file );
			policy_linux_file_content( socket: socket, file: directory + _file );
		}
	}
}
func zsql_command( socket, query ){
	var socket, query, cmd, output;
	if(!user = get_kb_item( "Policy/gaussdb/user" )){
		user = "SYS";
	}
	if(!password = get_kb_item( "Policy/gaussdb/password" )){
		password = "Changeme_123";
	}
	if(!ip = get_kb_item( "Policy/gaussdb/ip" )){
		ip = "127.0.0.1";
	}
	if(!port = get_kb_item( "Policy/gaussdb/port" )){
		port = "1611";
	}
	cmd = "zsql " + user + "/" + password + "@" + ip + ":" + port + " -q -c \"" + query + "\"";
	output = ssh_cmd( socket: socket, cmd: cmd, return_errors: FALSE, nosh: TRUE );
	if( !output ) {
		return;
	}
	else {
		return ( output );
	}
}
func mysql_command( socket, query ){
	var socket, query, cmd, output;
	if(!user = get_kb_item( "Policy/mysql/user" )){
		user = "root";
	}
	if(!password = get_kb_item( "Policy/mysql/password" )){
		password = "";
	}
	if(!ip = get_kb_item( "Policy/mysql/ip" )){
		ip = "127.0.0.1";
	}
	if(!port = get_kb_item( "Policy/mysql/port" )){
		port = "3306";
	}
	cmd = "mysql" + " --user=" + user + " --password=" + password + " --host=" + ip + " --port=" + port + " -sN -e \"" + query + "\"";
	output = ssh_cmd( socket: socket, cmd: cmd, return_errors: FALSE, nosh: TRUE );
	if( !output ) {
		return;
	}
	else {
		return ( output );
	}
}
func psql_command( socket, query ){
	var socket, query, cmd, output;
	if(!port = get_kb_item( "Policy/PostgreSQL/port" )){
		port = "5432";
	}
	cmd = "psql -c \"" + query + "\"" + " -p " + port;
	output = ssh_cmd( socket: socket, cmd: cmd, return_errors: FALSE, nosh: TRUE );
	if( !output ) {
		return;
	}
	else {
		return ( output );
	}
}
func policy_modprobe( module ){
	var module, sock, cmd, ret;
	if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
		return;
	}
	cmd = "modprobe -n -v " + module;
	ret = ssh_cmd( socket: sock, cmd: cmd );
	if(!ret){
		ret = "none";
	}
	return ( ret );
}
func policy_gsql_cmd( socket, query, db_type ){
	var socket, query, db_type, cmd, output;
	if( db_type == "gaussdbkernel" ){
		if(!database = get_kb_item( "Policy/gaussdbkernel/database" )){
			database = "postgres";
		}
		if(!port = get_kb_item( "Policy/gaussdbkernel/port" )){
			port = "8000";
		}
		use_su = get_kb_item( "Policy/gaussdbkernel/use_su" );
		if( use_su && ContainsString( use_su, "yes" ) ){
			su_user = get_kb_item( "Policy/gaussdbkernel/su_user" );
			cmd = "gsql -d " + database + " -p " + port + " -t -c \"" + query + "\"";
			cmd = str_replace( string: cmd, find: "'", replace: "\'\"\'\"\'" );
			cmd = "su - " + su_user + " -s /bin/bash -c '" + cmd + "'";
		}
		else {
			cmd = "gsql -d " + database + " -p " + port + " -t -c \"" + query + "\"";
		}
	}
	else {
		if(!database = get_kb_item( "Policy/opengauss/database" )){
			database = "postgres";
		}
		if(!port = get_kb_item( "Policy/opengauss/port" )){
			port = "26000";
		}
		use_su = get_kb_item( "Policy/opengauss/use_su" );
		if( use_su && ContainsString( use_su, "yes" ) ){
			su_user = get_kb_item( "Policy/opengauss/su_user" );
			cmd = "gsql -d " + database + " -p " + port + " -t -c \"" + query + "\"";
			cmd = str_replace( string: cmd, find: "'", replace: "\'\"\'\"\'" );
			cmd = "su - " + su_user + " -s /bin/bash -c '" + cmd + "'";
		}
		else {
			cmd = "gsql -d " + database + " -p " + port + " -t -c \"" + query + "\"";
		}
	}
	output = ssh_cmd( socket: socket, cmd: cmd, return_errors: TRUE, nosh: TRUE, nosu: TRUE );
	if( !output ) {
		return;
	}
	else {
		return ( output );
	}
}
func policy_access_permissions_string_to_numeric( perm ){
	var perm;
	var filemode_to_octal, owner, group, other, octal;
	if(!perm){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_access_permissions_string_to_numeric: perm empty" );
		return;
	}
	filemode_to_octal = make_array( "---", "0", "--x", "1", "-w-", "2", "-wx", "3", "r--", "4", "r-x", "5", "rw-", "6", "rwx", "7", "--S", "0", "-wS", "2", "r-S", "4", "rwS", "6", "--s", "1", "-ws", "3", "r-s", "5", "rws", "7", "--T", "0", "-wT", "2", "r-T", "4", "rwT", "6", "--t", "1", "-wt", "3", "r-t", "5", "rwt", "7" );
	owner = substr( perm, 0, 2 );
	group = substr( perm, 3, 5 );
	other = substr( perm, 6, 8 );
	octal = strcat( filemode_to_octal[owner], filemode_to_octal[group], filemode_to_octal[other] );
	if( octal ) {
		return ( octal );
	}
	else {
		return;
	}
}
func policy_access_permission_regex( filepath, socket ){
	var filepath, socket;
	var cmd, files, pattern, line, values, perm, file;
	if(!filepath || !socket){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#policy_access_permission_regex: filepath or socket empty" );
		return;
	}
	filepath = ereg_replace( string: filepath, pattern: "\n", replace: " " );
	cmd = "ls -la " + filepath;
	files = ssh_cmd( socket: socket, cmd: cmd, return_errors: TRUE );
	if(files){
		pattern = "[-d]([rwxtTsS-]{9})[^@[:space:]]+\\s+[0-9]+\\s+([^@[:space:]]+)\\s+([^@[:space:]]+).+\\s+([^@[:space:]]+)$";
		for line in split( buffer: files, keep: FALSE ) {
			values = eregmatch( string: chomp( line ), pattern: pattern );
			if(values){
				perm = policy_access_permissions_string_to_numeric( perm: values[1] );
				file = values[4];
				set_kb_item( name: "Policy/linux/" + file + "/user", value: values[2] );
				set_kb_item( name: "Policy/linux/" + file + "/group", value: values[3] );
				set_kb_item( name: "Policy/linux/" + file + "/perm", value: perm );
			}
		}
	}
}
func policy_vrp_command( socket, cmd ){
	var socket, cmd;
	var check_pattern, ret;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_vrp_command#-#socket" );
		return NULL;
	}
	if(!cmd){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#policy_vrp_command#-#cmd" );
		return NULL;
	}
	check_pattern = "^" + ereg_replace( string: cmd, pattern: "\\|\\s*", replace: "\\|?\\s*" ) + "\\s*<[^>]*>";
	ret = ssh_cmd( socket: socket, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE );
	if(!ret){
		return NULL;
	}
	ret = ereg_replace( string: ret, pattern: check_pattern, replace: "" );
	if(!ret){
		return NULL;
	}
	return ( ret );
}

