var optimize_test_enabled;
optimize_test_enabled = get_preference( "optimize_test" );
var _get_app_version_used, _get_app_location_used;
func register_host_detail( name, value, desc ){
	var name, value, desc;
	var nvt;
	if(!name){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#name#-#register_host_detail" );
		return;
	}
	if(!value){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#value#-#register_host_detail" );
	}
	nvt = get_script_oid();
	if(!nvt){
		return;
	}
	if(name != "port"){
		set_kb_item( name: "HostDetails", value: name );
		set_kb_item( name: "HostDetails/NVT", value: nvt );
		if(!isnull( desc )){
			replace_kb_item( name: "HostDetails/NVT/" + nvt, value: desc );
		}
	}
	if(value){
		set_kb_item( name: "HostDetails/NVT/" + nvt + "/" + name, value: value );
	}
}
func register_product( cpe, location, port, proto, service ){
	var cpe, location, port, proto, service;
	var base_cpe, kb_e;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#register_product" );
		return;
	}
	if(!location){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#location#-#register_product" );
		location = "/";
	}
	register_host_detail( name: "App", value: cpe );
	register_host_detail( name: cpe, value: location );
	if(port){
		register_host_detail( name: "port", value: port );
	}
	if(!base_cpe = get_base_cpe( cpe: cpe )){
		set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#register_product()#-#" + cpe + "#-#cpe" );
		base_cpe = cpe;
	}
	if(!proto){
		proto = "tcp";
	}
	if(isnull( port )){
		port = 0;
	}
	if( service ) {
		kb_e = get_script_oid() + "#-#" + cpe + "#-#" + location + "#-#" + port + "#-#" + proto + "#-#" + service;
	}
	else {
		kb_e = get_script_oid() + "#-#" + cpe + "#-#" + location + "#-#" + port + "#-#" + proto;
	}
	set_kb_item( name: "get_app/" + base_cpe, value: kb_e );
	if( port == 0 ) {
		set_kb_item( name: "get_app/ports/" + base_cpe, value: "local" );
	}
	else {
		set_kb_item( name: "get_app/ports/" + base_cpe, value: port );
	}
	set_kb_item( name: "get_app/protocols/" + base_cpe, value: proto );
	if(service){
		set_kb_item( name: "get_app/services/" + port + "/" + base_cpe, value: service );
	}
}
func host_details_list( key ){
	var key;
	return get_kb_list( "HostDetails/NVT/*/" + key );
}
func report_host_detail_single( name, value, nvt, desc ){
	var name, value, nvt, desc, report;
	if(!name){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#name#-#report_host_detail_single" );
	}
	if(!value){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#value#-#report_host_detail_single" );
	}
	if(!nvt){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#nvt#-#report_host_detail_single" );
	}
	report = "";
	report += xml_open_tag( tag: "host" );
	report += xml_open_tag( tag: "detail" );
	report += xml_tagline( tag: "name", value: name );
	report += xml_tagline( tag: "value", value: value );
	report += xml_open_tag( tag: "source" );
	report += xml_tagline( tag: "type", value: "nvt" );
	report += xml_tagline( tag: "name", value: nvt );
	if( !isnull( desc ) ) {
		report += xml_tagline( tag: "description", value: desc );
	}
	else {
		report += "<description/>";
	}
	report += xml_close_tag( tag: "source" );
	report += xml_close_tag( tag: "detail" );
	report += xml_close_tag( tag: "host" );
	log_message( proto: "Host_Details", data: report );
}
func report_host_details(  ){
	var names, nvts, _nvt, desc, _name, details, item;
	names = get_kb_list( "HostDetails" );
	nvts = get_kb_list( "HostDetails/NVT" );
	for _nvt in nvts {
		desc = get_kb_item( "HostDetails/NVT/" + _nvt );
		for _name in names {
			details = get_kb_list( "HostDetails/NVT/" + _nvt + "/" + _name );
			for _item in details {
				if(!isnull( _item )){
					report_host_detail_single( name: _name, value: _item, nvt: _nvt, desc: desc );
				}
			}
		}
	}
	os_report_best_cpe();
	os_report_best_txt();
}
func host_details_cpes(  ){
	var res, details_list, _item;
	res = make_list();
	details_list = host_details_list( key: "App" );
	if(!isnull( details_list )){
		for _item in details_list {
			if(ContainsString( _item, "cpe:/" )){
				res = make_list( res,
					 _item );
			}
		}
	}
	item = os_get_best_cpe();
	if(!isnull( item )){
		res = make_list( res,
			 item );
	}
	return res;
}
func get_app( cpe, loc ){
	var cpe, loc;
	var host_details, _host_detail, host_values, res, port, location, locations, l;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app" );
		return;
	}
	host_details = get_kb_list( "HostDetails/NVT/*" );
	if(!host_details){
		return NULL;
	}
	for _host_detail in keys( host_details ) {
		if(ContainsString( _host_detail, cpe )){
			host_values = split( buffer: _host_detail, sep: "/", keep: FALSE );
			if(isnull( host_values[2] ) || isnull( host_values[4] ) || !ContainsString( host_values[3], "cpe:" )){
				return NULL;
			}
			res = make_array();
			res["OID"] = host_values[2];
			res["CPE"] = "cpe:/" + host_values[4];
			port = get_kb_item( "HostDetails/NVT/" + res["OID"] + "/port" );
			if(port){
				res["port"] = port;
			}
			if( loc ){
				location = get_kb_item( "HostDetails/NVT/" + res["OID"] + "/" + res["CPE"] );
				res["LOCATION"] = location;
			}
			else {
				locations = get_kb_list( "HostDetails/NVT/" + res["OID"] + "/" + res["CPE"] );
				l = make_list( locations );
				if(max_index( l ) == 1){
					location = l[0];
				}
			}
			register_host_detail( name: "detected_by", value: res["OID"] );
			register_host_detail( name: "detected_at", value: location );
			return res;
		}
	}
	return NULL;
}
func get_app_version( cpe, port, service, nofork, version_regex ){
	var cpe, port, service, nofork, version_regex;
	_get_app_version_used = TRUE;
	if(_get_app_location_used){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_app_version() used together with get_app_location() in one single NVT. Please use get_app_version_and_location instead." );
	}
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app_version" );
		return;
	}
	if(NASLTypeof( cpe ) == "array"){
		if( !cpe[0] ){
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_app_version: List with an empty element passed to the 'cpe' parameter. Please only pass a single CPE in form of a string to this function." );
			return;
		}
		else {
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_app_version: Passing a list of CPEs to the 'cpe' parameter is deprecated / unsupported. Only using the first CPE from this list." );
			cpe = cpe[0];
		}
	}
	return get_app_details( cpe: cpe, type: "version", port: port, service: service, nofork: nofork, version_regex: version_regex );
}
func get_highest_app_version( cpe, port ){
	var cpe, port, ad, ret_version, _version;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_highest_app_version" );
		return;
	}
	ad = get_app_details( cpe: cpe, type: "all_versions", port: port );
	if(!ad){
		return;
	}
	ret_version = FALSE;
	for _version in ad {
		if(!ret_version){
			ret_version = _version;
			continue;
		}
		if(revcomp( a: _version, b: ret_version ) == 1){
			ret_version = _version;
		}
	}
	return ret_version;
}
func get_app_location( cpe, port, nofork, skip_port, default ){
	var cpe, port, nofork, skip_port, default;
	_get_app_location_used = TRUE;
	if(_get_app_version_used){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_app_version() used together with get_app_location() in one single NVT. Please use get_app_version_and_location instead." );
	}
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app_location" );
		return;
	}
	if(isnull( port ) && !nofork && !skip_port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#get_app_location" );
	}
	return get_app_details( cpe: cpe, type: "location", port: port, nofork: nofork, default: default );
}
func get_app_port_from_list( cpe_list, service, default, first_cpe_only ){
	var cpe_list, service, default, first_cpe_only;
	var oid, cpe_count, _cpe, base_cpe, _ports, _port, services, _service, infos, _infos, ret_arr;
	oid = get_script_oid();
	if(!cpe_list){
		set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#cpe_list#-#get_app_port_from_list" );
		return;
	}
	if(NASLTypeof( cpe_list ) != "array"){
		set_kb_item( name: "vt_debug_misc/" + oid, value: oid + "#-#get_app_port_from_list: No list passed to cpe_list parameter" );
		return;
	}
	cpe_count = 0;
	for _cpe in cpe_list {
		if(!base_cpe = get_base_cpe( cpe: _cpe )){
			set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#get_app_port_from_list()#-#" + _cpe + "#-#cpe_list" );
			continue;
		}
		if(isnull( _ports = get_kb_list( "get_app/ports/" + base_cpe ) )){
			continue;
		}
		cpe_count++;
		for _port in _ports {
			if(_port == "local"){
				_port = 0;
			}
			if( service ){
				services = get_kb_list( "get_app/services/" + _port + "/" + base_cpe );
				for _service in services {
					if(IsMatchRegexp( _port, "^[0-9]{1,5}$" ) && ContainsString( service, _service )){
						set_kb_item( name: "get_app/" + oid + "/port_cpe", value: _cpe + "#-#" + _port );
					}
				}
			}
			else {
				if(IsMatchRegexp( _port, "^[0-9]{1,5}$" )){
					set_kb_item( name: "get_app/" + oid + "/port_cpe", value: _cpe + "#-#" + _port );
				}
			}
		}
		if(first_cpe_only && cpe_count > 0){
			break;
		}
	}
	infos = get_kb_item( "get_app/" + oid + "/port_cpe" );
	if(!infos && default && optimize_test_enabled && ContainsString( optimize_test_enabled, "no" )){
		for _cpe in cpe_list {
			set_kb_item( name: "get_app/" + oid + "/port_cpe", value: _cpe + "#-#" + default );
		}
		infos = get_kb_item( "get_app/" + oid + "/port_cpe" );
	}
	if( infos ){
		_infos = split( buffer: infos, sep: "#-#", keep: FALSE );
		ret_arr["cpe"] = _infos[0];
		ret_arr["port"] = _infos[1];
		return ret_arr;
	}
	else {
		return;
	}
}
func get_app_version_from_list( cpe_list, port, nofork, version_regex ){
	var cpe_list, port, nofork, version_regex;
	var oid, _cpe, base_cpe, ap, ret_arr;
	oid = get_script_oid();
	if(!cpe_list){
		set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#cpe_list#-#get_app_version_from_list" );
		return;
	}
	if(NASLTypeof( cpe_list ) != "array"){
		set_kb_item( name: "vt_debug_misc/" + oid, value: oid + "#-#get_app_version_from_list: No list passed to cpe_list parameter" );
		return;
	}
	for _cpe in cpe_list {
		if(!base_cpe = get_base_cpe( cpe: _cpe )){
			set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#get_app_version_from_list()#-#" + _cpe + "#-#cpe_list" );
			continue;
		}
		if(isnull( get_kb_list( "get_app/ports/" + base_cpe ) )){
			continue;
		}
		set_kb_item( name: "get_app/" + oid + "/version_from_list", value: _cpe );
	}
	_cpe = get_kb_item( "get_app/" + oid + "/version_from_list" );
	if(_cpe){
		ap = get_app_details( cpe: _cpe, type: "version", port: port, nofork: nofork, version_regex: version_regex );
		if(ap){
			ret_arr["cpe"] = _cpe;
			ret_arr["version"] = ap;
			return ret_arr;
		}
	}
	return;
}
func get_app_location_from_list( cpe_list, port, nofork ){
	var cpe_list, port, nofork;
	var oid, _cpe, base_cpe, ap, ret_arr;
	oid = get_script_oid();
	if(!cpe_list){
		set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#cpe_list#-#get_app_location_from_list" );
		return;
	}
	if(NASLTypeof( cpe_list ) != "array"){
		set_kb_item( name: "vt_debug_misc/" + oid, value: oid + "#-#get_app_location_from_list: No list passed to cpe_list parameter" );
		return;
	}
	for _cpe in cpe_list {
		if(!base_cpe = get_base_cpe( cpe: _cpe )){
			set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#get_app_location_from_list()#-#" + _cpe + "#-#cpe_list" );
			continue;
		}
		if(isnull( get_kb_list( "get_app/ports/" + base_cpe ) )){
			continue;
		}
		set_kb_item( name: "get_app/" + oid + "/location_from_list", value: _cpe );
	}
	_cpe = get_kb_item( "get_app/" + oid + "/location_from_list" );
	if(_cpe){
		ap = get_app_details( cpe: _cpe, type: "location", port: port, nofork: nofork );
		if(ap){
			ret_arr["cpe"] = _cpe;
			ret_arr["location"] = ap;
			return ret_arr;
		}
	}
	return;
}
func get_app_version_and_location_from_list( cpe_list, port, exit_no_version, version_regex, default_location ){
	var cpe_list, port, exit_no_version, version_regex, default_location;
	var oid, _cpe, base_cpe, ap, ret_arr;
	oid = get_script_oid();
	if(!cpe_list){
		set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#cpe_list#-#get_app_version_from_list" );
		return;
	}
	if(NASLTypeof( cpe_list ) != "array"){
		set_kb_item( name: "vt_debug_misc/" + oid, value: oid + "#-#get_app_version_from_list: No list passed to cpe_list parameter" );
		return;
	}
	for _cpe in cpe_list {
		if(!base_cpe = get_base_cpe( cpe: _cpe )){
			set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#get_app_version_and_location_from_list()#-#" + _cpe + "#-#cpe_list" );
			continue;
		}
		if(isnull( get_kb_list( "get_app/ports/" + base_cpe ) )){
			continue;
		}
		set_kb_item( name: "get_app/" + oid + "/version_and_location_from_list", value: _cpe );
	}
	_cpe = get_kb_item( "get_app/" + oid + "/version_and_location_from_list" );
	if(_cpe){
		ap = get_app_details( cpe: _cpe, type: "version_location", port: port, exit_no_version: exit_no_version, version_regex: version_regex, default_location: default_location );
		if(isnull( ap ) && exit_no_version){
			exit( 0 );
		}
		if(ap && !ap["version"] && exit_no_version){
			exit( 0 );
		}
		ret_arr = ap;
		ret_arr["cpe"] = _cpe;
		return ret_arr;
	}
	return;
}
func get_app_port( cpe, service, default ){
	var cpe, service, default;
	var base_cpe, port, services;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app_port" );
		return;
	}
	if(NASLTypeof( cpe ) == "array"){
		if( !cpe[0] ){
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_app_port: List with an empty element passed to the 'cpe' parameter. Please only pass a single CPE in form of a string to this function." );
			return;
		}
		else {
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_app_port: Passing a list of CPEs to the 'cpe' parameter is deprecated / unsupported. Only using the first CPE from this list." );
			cpe = cpe[0];
		}
	}
	if(!base_cpe = get_base_cpe( cpe: cpe )){
		set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#get_app_port()#-#" + cpe + "#-#cpe" );
		return;
	}
	port = get_kb_item( "get_app/ports/" + base_cpe );
	if(port == "local"){
		port = 0;
	}
	if( service ){
		services = get_kb_item( "get_app/services/" + port + "/" + base_cpe );
		if(IsMatchRegexp( port, "^[0-9]{1,5}$" ) && ContainsString( service, services )){
			return port;
		}
	}
	else {
		if(IsMatchRegexp( port, "^[0-9]{1,5}$" )){
			return port;
		}
	}
	if( default && optimize_test_enabled && ContainsString( optimize_test_enabled, "no" ) ) {
		return default;
	}
	else {
		return;
	}
}
func get_app_version_and_location( cpe, port, exit_no_version, version_regex, default_location ){
	var cpe, port, exit_no_version, version_regex, default_location;
	var app_details;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app_version_and_location" );
		return;
	}
	app_details = get_app_details( cpe: cpe, type: "version_location", port: port, exit_no_version: exit_no_version, version_regex: version_regex, default_location: default_location );
	if(isnull( app_details ) && exit_no_version){
		exit( 0 );
	}
	if(app_details && !app_details["version"] && exit_no_version){
		exit( 0 );
	}
	return app_details;
}
func get_app_location_and_proto( cpe, port, default_location, default_proto ){
	var cpe, port, default_location, default_proto;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app_location_and_proto" );
		return;
	}
	return get_app_details( cpe: cpe, type: "location_proto", port: port, default_location: default_location, default_proto: default_proto );
}
func get_app_version_and_proto( cpe, port, exit_no_version, default_proto ){
	var cpe, port, exit_no_version, default_proto;
	var app_details;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app_version_and_proto" );
		return;
	}
	app_details = get_app_details( cpe: cpe, type: "version_proto", port: port, exit_no_version: exit_no_version, default_proto: default_proto );
	if(isnull( app_details ) && exit_no_version){
		exit( 0 );
	}
	if(app_details && !app_details["version"] && exit_no_version){
		exit( 0 );
	}
	return app_details;
}
func get_app_full( cpe, port, exit_no_version ){
	var cpe, port, exit_no_version;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app_full" );
		return;
	}
	return get_app_details( cpe: cpe, type: "full", port: port, exit_no_version: exit_no_version );
}
func get_app_port_from_cpe_prefix( cpe, default, service, first_cpe_only ){
	var cpe, default, service, first_cpe_only;
	var data, _cpelist, _entry, parts, _cpe;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app_port_from_cpe_prefix" );
		return;
	}
	data = get_kb_list( "get_app/ports/" + cpe + "*" );
	if(!data){
		return;
	}
	_cpelist = make_list();
	for _entry in keys( data ) {
		if(!ContainsString( _entry, cpe )){
			continue;
		}
		parts = split( buffer: _entry, sep: "/", keep: FALSE );
		if(max_index( parts ) < 4){
			continue;
		}
		if(parts[2] != "cpe:"){
			continue;
		}
		_cpe = parts[2] + "/" + parts[3];
		if(!ContainsString( _cpe, cpe )){
			continue;
		}
		_cpelist = make_list( _cpelist,
			 _cpe );
	}
	return get_app_port_from_list( cpe_list: _cpelist, service: service, default: default, first_cpe_only: first_cpe_only );
}
func get_app_details( cpe, type, port, exit_no_version, service, nofork, version_regex, default, default_location, default_proto ){
	var cpe, type, port, exit_no_version, service, nofork, version_regex, default, default_location, default_proto;
	var base_cpe, version_list, ap, _dt, t, t_cpe, t_port, app_versions, app_locations;
	var t_oid, t_loc, app_details, x, x_oid, x_cpe, x_loc, x_port, x_proto, x_service, ret_arr;
	if(!cpe){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_app_details" );
		return;
	}
	if(!base_cpe = get_base_cpe( cpe: cpe )){
		set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#get_app_details()#-#" + cpe + "#-#cpe" );
		return;
	}
	if( type == "all_versions" ){
		version_list = make_list();
		ap = get_kb_list( "get_app/" + base_cpe );
		if(!ap){
			return;
		}
		for _dt in ap {
			t = split( buffer: _dt, sep: "#-#", keep: FALSE );
			t_cpe = t[1];
			if(!t_cpe){
				continue;
			}
			t_port = t[3];
			if(!isnull( port ) && int( t_port ) != int( port )){
				continue;
			}
			if(!app_versions = get_version_from_cpe( cpe: t_cpe )){
				continue;
			}
			version_list = make_list( version_list,
				 app_versions );
		}
		register_host_detail( name: "detected_by", value: t[0] );
		if(!isnull( t[2] )){
			register_host_detail( name: "detected_at", value: t[2] );
		}
		return version_list;
	}
	else {
		if( nofork && type == "version" ){
			ap = get_kb_list( "get_app/" + base_cpe );
			if(!ap){
				return;
			}
			for _dt in ap {
				t = split( buffer: _dt, sep: "#-#", keep: FALSE );
				t_cpe = t[1];
				if(!t_cpe){
					continue;
				}
				t_port = t[3];
				if(!isnull( port ) && int( t_port ) != int( port )){
					continue;
				}
				if(!app_versions = get_version_from_cpe( cpe: t_cpe )){
					continue;
				}
				if(version_regex && !ereg( pattern: version_regex, string: app_versions )){
					continue;
				}
				register_host_detail( name: "detected_by", value: t[0] );
				if(!isnull( t[2] )){
					register_host_detail( name: "detected_at", value: t[2] );
				}
				return app_versions;
			}
			return;
		}
		else {
			if( nofork && type == "location" ){
				ap = get_kb_list( "get_app/" + base_cpe );
				if( !ap && default && optimize_test_enabled && ContainsString( optimize_test_enabled, "no" ) ) {
					return make_list( default );
				}
				else {
					if(!ap){
						return;
					}
				}
				app_locations = make_list();
				for _dt in ap {
					t = split( buffer: _dt, sep: "#-#", keep: FALSE );
					t_oid = t[0];
					t_loc = t[2];
					if(isnull( t_oid ) && isnull( t_loc )){
						continue;
					}
					t_port = t[3];
					if(!isnull( port ) && int( t_port ) != int( port )){
						continue;
					}
					register_host_detail( name: "detected_by", value: t_oid );
					if(!isnull( t[2] )){
						register_host_detail( name: "detected_at", value: t_loc );
					}
					app_locations = make_list( app_locations,
						 t_loc );
				}
				return app_locations;
			}
			else {
				app_details = get_kb_item( "get_app/" + base_cpe );
			}
		}
	}
	if( !app_details && optimize_test_enabled && ContainsString( optimize_test_enabled, "no" ) ){
		if( type == "location" && default ){
			return default;
		}
		else {
			if( type == "version_location" && default_location ){
				ret_arr["version"] = "";
				ret_arr["location"] = default_location;
				return ret_arr;
			}
			else {
				if( type == "version_proto" && default_proto ){
					ret_arr["version"] = "";
					ret_arr["proto"] = default_proto;
					return ret_arr;
				}
				else {
					if( type == "location_proto" && ( default_proto || default_location ) ){
						if( default_proto ) {
							ret_arr["proto"] = default_proto;
						}
						else {
							ret_arr["proto"] = "tcp";
						}
						if( default_location ) {
							ret_arr["location"] = default_location;
						}
						else {
							ret_arr["location"] = "";
						}
						return ret_arr;
					}
					else {
						return;
					}
				}
			}
		}
	}
	else {
		if(!app_details){
			return;
		}
	}
	x = split( buffer: app_details, sep: "#-#", keep: FALSE );
	x_oid = x[0];
	x_cpe = x[1];
	x_loc = x[2];
	x_port = x[3];
	x_proto = x[4];
	if(x[5]){
		x_service = x[5];
	}
	if(service && x_service != service){
		return;
	}
	if(!isnull( port ) && int( x_port ) != int( port )){
		return;
	}
	if(type == "version"){
		if(!app_versions = get_version_from_cpe( cpe: x_cpe )){
			return;
		}
		if(version_regex && !ereg( pattern: version_regex, string: app_versions )){
			return;
		}
		register_host_detail( name: "detected_by", value: x_oid );
		if(x_loc){
			register_host_detail( name: "detected_at", value: x_loc );
		}
		return app_versions;
	}
	if(type == "location"){
		if(x_loc){
			register_host_detail( name: "detected_by", value: x_oid );
			if(x_loc){
				register_host_detail( name: "detected_at", value: x_loc );
			}
			return x_loc;
		}
		return;
	}
	if(type == "version_location"){
		app_versions = get_version_from_cpe( cpe: x_cpe );
		if(!app_versions && exit_no_version == TRUE){
			exit( 0 );
		}
		if(!app_versions && !x_loc){
			return;
		}
		if( app_versions ){
			if(version_regex && !ereg( pattern: version_regex, string: app_versions )){
				return;
			}
			ret_arr["version"] = app_versions;
		}
		else {
			ret_arr["version"] = "";
		}
		if( x_loc ) {
			ret_arr["location"] = x_loc;
		}
		else {
			ret_arr["location"] = "";
		}
		register_host_detail( name: "detected_by", value: x_oid );
		if(x_loc){
			register_host_detail( name: "detected_at", value: x_loc );
		}
		return ret_arr;
	}
	if(type == "version_proto"){
		app_versions = get_version_from_cpe( cpe: x_cpe );
		if(!app_versions && exit_no_version == TRUE){
			exit( 0 );
		}
		if(!app_versions && !x_proto){
			return;
		}
		if( app_versions ) {
			ret_arr["version"] = app_versions;
		}
		else {
			ret_arr["version"] = "";
		}
		if( x_proto ) {
			ret_arr["proto"] = x_proto;
		}
		else {
			ret_arr["proto"] = "tcp";
		}
		register_host_detail( name: "detected_by", value: x_oid );
		if(x_proto && x_port){
			register_host_detail( name: "detected_at", value: x_port + "/" + x_proto );
		}
		return ret_arr;
	}
	if(type == "location_proto"){
		if( x_proto ) {
			ret_arr["proto"] = x_proto;
		}
		else {
			ret_arr["proto"] = "tcp";
		}
		if( x_loc ) {
			ret_arr["location"] = x_loc;
		}
		else {
			ret_arr["location"] = "";
		}
		register_host_detail( name: "detected_by", value: x_oid );
		if(x_loc){
			register_host_detail( name: "detected_at", value: x_loc );
		}
		return ret_arr;
	}
	if(type == "full"){
		app_versions = get_version_from_cpe( cpe: x_cpe );
		if(!app_versions && exit_no_version == TRUE){
			exit( 0 );
		}
		ret_arr["version"] = app_versions;
		ret_arr["location"] = x_loc;
		ret_arr["full_cpe"] = x_cpe;
		ret_arr["port"] = x_port;
		ret_arr["proto"] = x_proto;
		if(x_service){
			ret_arr["service"] = x_service;
		}
		ret_arr["detected_by"] = x_oid;
		register_host_detail( name: "detected_by", value: x_oid );
		if(x_loc){
			register_host_detail( name: "detected_at", value: x_loc );
		}
		return ret_arr;
	}
	return;
}
func get_version_from_cpe( cpe ){
	var cpe, tokens, token_val, app_versions;
	if(isnull( cpe )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cpe#-#get_version_from_cpe" );
		return;
	}
	tokens = split( buffer: cpe, sep: ":", keep: FALSE );
	if(!isnull( tokens[4] )){
		if( tokens[4] == "x64" ) {
			token_val = 1;
		}
		else {
			token_val = 0;
		}
		if( !isnull( tokens[5 + token_val] ) && tokens[5 + token_val] != "-" && tokens[5 + token_val] != "" ){
			if( tokens[4 + token_val] != "-" && tokens[4 + token_val] != "" ) {
				app_versions = tokens[4 + token_val] + "" + tokens[5 + token_val];
			}
			else {
				app_versions = tokens[5 + token_val];
			}
		}
		else {
			if(tokens[4 + token_val] != "-" && tokens[4 + token_val] != ""){
				app_versions = tokens[4 + token_val];
			}
		}
	}
	if( !app_versions ) {
		return;
	}
	else {
		return app_versions;
	}
}
func get_base_cpe( cpe ){
	var cpe, bc, base_cpe;
	if(!cpe){
		return;
	}
	bc = split( buffer: cpe, sep: ":", keep: FALSE );
	if(!bc || max_index( bc ) < 4){
		return;
	}
	if(bc[0] != "cpe" || !IsMatchRegexp( bc[1], "/(a|o|h)$" )){
		return;
	}
	base_cpe = bc[0] + ":" + bc[1] + ":" + bc[2] + ":" + bc[3];
	return base_cpe;
}
func build_detection_report( app, version, patch, build, install, regpath, cpe, concluded, concludedUrl, extra, skip_version ){
	var app, version, patch, build, install, regpath, cpe, concluded, concludedUrl, extra, skip_version, report;
	if(isnull( app )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#app#-#build_detection_report" );
	}
	report = "Detected " + app + "\n";
	if(!skip_version){
		if(!version){
			version = "unknown";
		}
		report += "\nVersion:       " + version;
	}
	if(patch && patch != "unknown"){
		report += "\nPatch/Update:  " + patch;
	}
	if(build && build != "unknown"){
		report += "\nBuild:         " + build;
	}
	report += "\nLocation:      " + install;
	if(strlen( cpe ) > 0){
		report += "\nCPE:           " + cpe;
	}
	if(strlen( regpath ) > 0){
		report += "\nRegistry path: " + regpath;
	}
	if(strlen( concluded ) > 0 && tolower( concluded ) != "unknown"){
		report += "\n\nConcluded from version/product identification result:\n" + concluded;
	}
	if(strlen( concludedUrl ) > 0){
		report += "\n\nConcluded from version/product identification location:\n" + concludedUrl;
	}
	if(strlen( extra ) > 0){
		report += "\n\nExtra information:\n" + extra;
	}
	return report;
}

