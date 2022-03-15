valid_snmpv3_errors = make_list( "Unknown user name",
	 "Unsupported security level",
	 "Generic error",
	 "Session abort failure",
	 "Unknown security model in message",
	 "MIB not initialized",
	 "Authentication failure (incorrect password, community or key)" );
invalid_snmpv3_creds_errors = make_list( "Missing function argument",
	 "Invalid port value",
	 "Invalid protocol value",
	 "Missing privproto or privpass",
	 "authproto should be md5 or sha1",
	 "privproto should be des or aes" );
var snmp_error, v3_creds, valid_snmpv3_errors, invalid_snmpv3_creds_errors, last_snmp_error, _snmp_func_debug;
_snmp_func_debug = FALSE;
func snmp_check_v1( port, community ){
	var port, community, oid, protocol, ret;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#snmp_check_v1" );
		return;
	}
	if(!community){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#community#-#snmp_check_v1" );
		return;
	}
	oid = "1.3.6.1.2.1.1.1.0";
	protocol = "udp";
	ret = snmpv1_get( port: port, oid: oid, protocol: protocol, community: community );
	if(ret[0] < 0){
		return;
	}
	if(ret[0] == 0 && !isnull( ret[1] )){
		return TRUE;
	}
	return;
}
func snmp_check_v2( port, community ){
	var port, community, oid, protocol, ret;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#snmp_check_v2" );
		return;
	}
	if(!community){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#community#-#snmp_check_v2" );
		return;
	}
	oid = "1.3.6.1.2.1.1.1.0";
	protocol = "udp";
	ret = snmpv2c_get( port: port, oid: oid, protocol: protocol, community: community );
	if(int( ret[0] ) < 0){
		return;
	}
	if(ret[0] == 0 && !isnull( ret[1] )){
		return TRUE;
	}
	return;
}
func snmp_check_v3( port ){
	var port;
	var oid, protocol, snmpv3_username, vt_strings, snmpv3_password;
	var snmpv3_authalgo, snmpv3_privpass, snmpv3_privalgo, ret;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#snmp_check_v3" );
		return;
	}
	oid = "1.3.6.1.2.1.1.1.0";
	protocol = "udp";
	snmpv3_username = get_kb_item( "SNMP/v3/username" );
	if( !snmpv3_username || ( strlen( snmpv3_username ) == 0 ) ){
		vt_strings = get_vt_strings();
		snmpv3_username = vt_strings["lowercase"];
		snmpv3_password = vt_strings["lowercase"];
		snmpv3_authalgo = "md5";
		snmpv3_privpass = vt_strings["lowercase"];
		snmpv3_privalgo = "des";
	}
	else {
		snmpv3_password = get_kb_item( "SNMP/v3/password" );
		snmpv3_authalgo = get_kb_item( "SNMP/v3/auth_algorithm" );
		if( !snmpv3_privpass = get_kb_item( "SNMP/v3/privacy_password" ) ) {
			snmpv3_privalgo = NULL;
		}
		else {
			snmpv3_privalgo = get_kb_item( "SNMP/v3/privacy_algorithm" );
		}
		v3_creds = TRUE;
	}
	ret = snmpv3_get( port: port, protocol: protocol, username: snmpv3_username, oid: oid, authpass: snmpv3_password, authproto: snmpv3_authalgo, privpass: snmpv3_privpass, privproto: snmpv3_privalgo );
	if(ret[0] == -1){
		snmp_error = ret[1];
		if( in_array( array: valid_snmpv3_errors, search: snmp_error ) ) {
			return 2;
		}
		else {
			return;
		}
	}
	if(ret[0] == 0 && !isnull( ret[1] )){
		return 1;
	}
	if(ret[0] == -2){
		snmp_error = ret[1];
	}
	return;
}
func snmp_get( port, oid, version, community ){
	var port, oid, version, community, ret;
	var v3_username, v3_password, v3_authalgo, v3_privpass, v3_privalgo;
	if(!defined_func( "snmpv3_get" )){
		report = "snmp_get: The scanner/libraries are not build with libsnmp support. Advanced SNMP checks will fail.";
		report += " Please rebuild with SNMP support enabled.";
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#" + report );
		return;
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#snmp_get" );
		return;
	}
	if(!oid){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#oid#-#snmp_get" );
		return;
	}
	if(!version){
		version = get_kb_item( "SNMP/" + port + "/preferred_version" );
	}
	if(!version){
		return;
	}
	if(version == 3){
		if(get_kb_item( "SNMP/" + port + "/v3/working" )){
			v3_username = get_kb_item( "SNMP/v3/username" );
			v3_password = get_kb_item( "SNMP/v3/password" );
			v3_authalgo = get_kb_item( "SNMP/v3/auth_algorithm" );
			v3_privpass = get_kb_item( "SNMP/v3/privacy_password" );
			v3_privalgo = get_kb_item( "SNMP/v3/privacy_algorithm" );
			if(v3_username && v3_username != ""){
				if(!v3_privpass){
					v3_privalgo = NULL;
				}
				ret = snmpv3_get( port: port, protocol: "udp", username: v3_username, oid: oid, authpass: v3_password, authproto: v3_authalgo, privpass: v3_privpass, privproto: v3_privalgo );
				if(ret[0] != 0 || snmp_is_error_message( ret[1] )){
					last_snmp_error = ret[1];
					if(_snmp_func_debug){
						display( "SNMP debug: Received error in snmpv3_get " + last_snmp_error );
					}
					return;
				}
				if(ret[0] == 0 && !snmp_is_error_message( ret[1] )){
					return snmp_clean_ret( ret[1] );
				}
			}
		}
	}
	if(version == 2){
		if(get_kb_item( "SNMP/" + port + "/v2c/working" )){
			if(!community){
				community = snmp_get_community( port: port, version: 2 );
			}
			if(community && community != ""){
				ret = snmpv2c_get( port: port, oid: oid, protocol: "udp", community: community );
				if(ret[0] != 0 || snmp_is_error_message( ret[1] )){
					last_snmp_error = ret[1];
					if(_snmp_func_debug){
						display( "SNMP debug: Received error in snmpv2c_get " + last_snmp_error );
					}
					return;
				}
				if(ret[0] == 0 && !snmp_is_error_message( ret[1] )){
					return snmp_clean_ret( ret[1] );
				}
			}
		}
	}
	if(version == 1){
		if(get_kb_item( "SNMP/" + port + "/v1/working" )){
			if(!community){
				community = snmp_get_community( port: port, version: 1 );
			}
			if(community && community != ""){
				ret = snmpv1_get( port: port, oid: oid, protocol: "udp", community: community );
				if(ret[0] != 0 || snmp_is_error_message( ret[1] )){
					last_snmp_error = ret[1];
					if(_snmp_func_debug){
						display( "SNMP debug: Received error in snmpv1_get " + last_snmp_error );
					}
					return;
				}
				if(ret[0] == 0 && !snmp_is_error_message( ret[1] )){
					return snmp_clean_ret( ret[1] );
				}
			}
		}
	}
	return;
}
func snmp_clean_ret(  ){
	var arg;
	arg = _FCT_ANON_ARGS[0];
	if(!arg){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#snmp_clean_ret" );
		return;
	}
	return ereg_replace( pattern: "^\"(.*)\"$", string: arg, replace: "\\1" );
}
func snmp_get_community( port, version ){
	var port, version, ckey, clist;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#snmp_get_community" );
		return;
	}
	if(!version){
		version = get_kb_item( "SNMP/" + port + "/preferred_version" );
	}
	if(!version){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#snmp_get_community: couldn't determine SNMP version / no SNMP version available" );
		return;
	}
	if( version == 1 ) {
		ckey = "SNMP/" + port + "/v1/community";
	}
	else {
		if( version == 2 ) {
			ckey = "SNMP/" + port + "/v2c/community";
		}
		else {
			return;
		}
	}
	clist = get_kb_list( ckey );
	if(!clist){
		return;
	}
	clist = make_list( clist );
	return clist[0];
}
func snmp_is_error_message(  ){
	var message, errors, _error;
	message = _FCT_ANON_ARGS[0];
	if(!message){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#snmp_is_error_message" );
		return;
	}
	errors = make_list( "No Such Object available on this agent at this OID",
		 "No Such Instance" );
	for _error in errors {
		if(ContainsString( message, _error )){
			return TRUE;
		}
	}
	return;
}
func snmp_get_sw_oid( pattern, port ){
	var pattern, port, list, split, i, result;
	if(!pattern || pattern == ""){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#pattern#-#snmp_get_sw_oid" );
		return;
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#snmp_get_sw_oid" );
		return;
	}
	if(!list = get_kb_item( "SNMP/" + port + "/installed_software" )){
		return;
	}
	split = split( buffer: list, sep: "|", keep: FALSE );
	i = 0;
	for(;i < max_index( split );){
		if(ereg( pattern: pattern, string: split[i + 1] )){
			result = make_array( "oid", split[i], "package", split[i + 1] );
			return result;
		}
		i += 2;
	}
}
func snmp_get_port( default ){
	var default;
	var port;
	port = get_kb_item( "Services/udp/snmp" );
	if(port){
		default = port;
	}
	if(!get_udp_port_state( default )){
		exit( 0 );
	}
	return default;
}
func snmp_get_sysdescr( port ){
	var port;
	var sysdescr;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#snmp_get_sysdescr" );
		return;
	}
	sysdescr = get_kb_item( "SNMP/" + port + "/sysdescr" );
	if(!sysdescr){
		return;
	}
	return sysdescr;
}

