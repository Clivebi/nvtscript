func build_cpe( value, exp, base ){
	var value, exp, base;
	var res, last;
	if(!value){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#value#-#build_cpe" );
		return NULL;
	}
	if(!exp){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#exp#-#build_cpe" );
		return NULL;
	}
	if(!base){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#base#-#build_cpe" );
		return NULL;
	}
	if(!get_base_cpe( cpe: base )){
		set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#build_cpe()#-#" + base + "#-#base" );
		return NULL;
	}
	if(value == "unknown" || value == "Unknown" || strlen( value ) < 1){
		return NULL;
	}
	res = eregmatch( string: value, pattern: exp, icase: TRUE );
	if(res[1]){
		last = strlen( base ) - 1;
		if( !ContainsString( base[last], ":" ) ){
			return base;
		}
		else {
			if( res[1] && res[2] ){
				return NASLString( base, res[1], ":", res[2] );
			}
			else {
				if(res[1]){
					return NASLString( base, res[1] );
				}
			}
		}
	}
	return NULL;
}
func register_and_report_cpe( app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra ){
	var app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra;
	if(!cpename && !base && !expr){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpename,base,expr#-#register_and_report_cpe" );
		return NULL;
	}
	if(!cpename && ( base && !expr )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#expr#-#register_and_report_cpe" );
		return NULL;
	}
	if(!cpename && ( !base && expr )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#base#-#register_and_report_cpe" );
		return NULL;
	}
	if(cpename && base){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#register_and_report_cpe(): cpename and base parameter given, please use only one!" );
	}
	if(cpename && !get_base_cpe( cpe: cpename )){
		set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#register_and_report_cpe()#-#" + cpename + "#-#cpename" );
		return NULL;
	}
	if(base && !get_base_cpe( cpe: base )){
		set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#register_and_report_cpe()#-#" + base + "#-#base" );
		return NULL;
	}
	if(!insloc){
		insloc = "unknown";
	}
	if(!concluded && ver){
		concluded = ver;
	}
	if(!ver || ver == "" || ver == "Unknown"){
		ver = "unknown";
	}
	if(!regProto){
		regProto = "tcp";
	}
	if(isnull( regPort )){
		regPort = 0;
	}
	if(!cpename && base){
		cpename = build_cpe( value: ver, exp: expr, base: base );
		if(!cpename || ver == "unknown"){
			cpename = ereg_replace( pattern: ":$", string: base, replace: "" );
		}
	}
	if(cpename){
		register_product( cpe: cpename, location: insloc, port: regPort, proto: regProto, service: regService );
		log_message( data: build_detection_report( app: app, version: ver, install: insloc, cpe: cpename, extra: extra, concluded: concluded, concludedUrl: conclUrl ), port: regPort, proto: regProto );
	}
	return NULL;
}

