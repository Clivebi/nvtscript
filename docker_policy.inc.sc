var dockerd, docker_port_values, docker_activated_tests, docker_failed_tests, docker_success_tests, docker_skipped_tests, docker_error_tests;
var _docker_pid, _docker_socket, _docker_service_file, _docker_running_containers, _docker_help, _docker_cmd, _docker_info;
func get_minimum_docker_test_version(  ){
	_minimum_docker_test_version = script_get_preference( "Minimum docker version for test 1.1:" );
	if(!_minimum_docker_test_version || !IsMatchRegexp( _minimum_docker_test_version, "^[0-9.]+" )){
		_minimum_docker_test_version = "1.13";
	}
	return _minimum_docker_test_version;
}
func get_docker_help_banner(  ){
	var help;
	if( !isnull( _docker_help ) ){
		help = NASLString( _docker_help );
	}
	else {
		help = docker_run_cmd( cmd: dockerd + "--help" );
		if( help ){
			_docker_help = NASLString( help );
		}
		else {
			help = "";
			_docker_help = help;
		}
	}
	return help;
}
func get_docker_cmd(  ){
	var cmd;
	if( !isnull( _docker_cmd ) ){
		cmd = NASLString( _docker_cmd );
	}
	else {
		cmd = docker_read_cmd_line();
		if( cmd ){
			_docker_cmd = NASLString( cmd );
		}
		else {
			cmd = "";
			_docker_cmd = cmd;
		}
	}
	return cmd;
}
func get_docker_info(  ){
	var info;
	if( !isnull( _docker_info ) ){
		info = NASLString( _docker_info );
	}
	else {
		info = get_kb_item( "docker/info" );
		if( info ){
			_docker_info = NASLString( info );
		}
		else {
			info = "";
			_docker_info = info;
		}
	}
	return info;
}
func get_docker_running_containers(  ){
	var containers;
	if( !isnull( _docker_running_containers ) ){
		containers = _docker_running_containers;
	}
	else {
		containers = docker_build_running_containers_array();
		if( containers ){
			_docker_running_containers = containers;
		}
		else {
			containers = "";
			_docker_running_containers = containers;
		}
	}
	return containers;
}
func get_docker_service_file(  ){
	var file;
	if( !isnull( _docker_service_file ) ){
		file = NASLString( _docker_service_file );
	}
	else {
		file = docker_systemd_file( file: "docker.service" );
		if( file ){
			_docker_service_file = NASLString( file );
		}
		else {
			file = "";
			_docker_service_file = file;
		}
	}
	return file;
}
func get_docker_socket(  ){
	var socket;
	if( !isnull( _docker_socket ) ){
		socket = NASLString( _docker_socket );
	}
	else {
		socket = docker_systemd_file( file: "docker.socket" );
		if( socket ){
			_docker_socket = NASLString( socket );
		}
		else {
			socket = "";
			_docker_socket = socket;
		}
	}
	return socket;
}
func get_docker_pid(  ){
	var pid;
	if( !isnull( _docker_pid ) ){
		pid = NASLString( _docker_pid );
	}
	else {
		pid = docker_run_cmd( cmd: "ps -ef | grep -e '[/]docker[d ]' | awk '{ print $2 }'" );
		if( pid ){
			_docker_pid = NASLString( pid );
		}
		else {
			pid = "";
			_docker_pid = pid;
		}
	}
	return pid;
}
func docker_test_init(  ){
	var perform_check, report_passed, report_failed, report_errors, report_skipped;
	var _dt, pid, docker_cmd, docker_info, docker_running_containers, docker_service_file;
	docker_activated_tests = make_list();
	perform_check = script_get_preference( "Perform check:" );
	if(!perform_check || perform_check != "yes"){
		exit( 0 );
	}
	report_passed = script_get_preference( "Report passed tests:" );
	if(report_passed && report_passed == "yes"){
		set_kb_item( name: "docker/docker_test/report_passed", value: TRUE );
	}
	report_failed = script_get_preference( "Report failed tests:" );
	if(report_failed && report_failed == "yes"){
		set_kb_item( name: "docker/docker_test/report_failed", value: TRUE );
	}
	report_errors = script_get_preference( "Report errors:" );
	if(report_errors && report_errors == "yes"){
		set_kb_item( name: "docker/docker_test/report_errors", value: TRUE );
	}
	report_skipped = script_get_preference( "Report skipped tests:" );
	if(report_skipped && report_skipped == "yes"){
		set_kb_item( name: "docker/docker_test/report_skipped", value: TRUE );
	}
	for _dt in docker_test {
		pref = script_get_preference( _dt["title"] );
		if(pref && pref == "yes"){
			id = eregmatch( pattern: "^([0-9.]+)", string: _dt["title"] );
			if(!isnull( id[1] )){
				docker_activated_tests = make_list( docker_activated_tests,
					 id[1] );
			}
		}
	}
	pid = get_docker_pid();
	if(!pid || !IsMatchRegexp( pid, "^[0-9]+$" )){
		log_message( port: 0, data: "Docker Policy test failed. No running docker daemon found.\n" );
		exit( 0 );
	}
	docker_cmd = get_docker_cmd();
	if(!docker_cmd){
		log_message( port: 0, data: "Docker Policy test failed. Unable to read docker daemon command line.\n" );
		exit( 0 );
	}
	if( ContainsString( get_docker_cmd(), "dockerd" ) ) {
		dockerd = "dockerd ";
	}
	else {
		if( ContainsString( get_docker_cmd(), "docker daemon" ) ) {
			dockerd = "docker daemon ";
		}
		else {
			dockerd = "docker ";
		}
	}
	docker_info = get_docker_info();
	if(!docker_info || ContainsString( docker_info, "Cannot connect to the Docker daemon" )){
		log_message( port: 0, data: "Docker Policy test failed. No running docker daemon found or the user has no permissions to connect to the docker daemon.\n" );
		exit( 0 );
	}
	set_kb_item( name: "docker/docker_test/docker_cmd", value: docker_cmd );
	docker_running_containers = get_docker_running_containers();
	if(!docker_running_containers){
		log_message( port: 0, data: "No running containers found. Some checks are skipped.\n" );
	}
	docker_service_file = get_docker_service_file();
	if(!docker_service_file){
		log_message( port: 0, data: "Not a systemd system. Systemd checks are skipped.\n" );
	}
	docker_port_values = docker_port_values();
}
func docker_test_end(  ){
	if(docker_failed_tests > 0){
		set_kb_item( name: "docker/docker_test/has_failed_tests", value: TRUE );
	}
	if(docker_success_tests > 0){
		set_kb_item( name: "docker/docker_test/has_success_tests", value: TRUE );
	}
	if(docker_skipped_tests > 0){
		set_kb_item( name: "docker/docker_test/has_skipped_tests", value: TRUE );
	}
	if(docker_error_tests > 0){
		set_kb_item( name: "docker/docker_test/has_error_tests", value: TRUE );
	}
}
func docker_test_set_failed( id, reason ){
	var id, reason;
	if(!reason){
		reason = "-";
	}
	set_kb_item( name: "docker/docker_test/failed/" + id, value: reason );
	docker_failed_tests++;
}
func docker_test_set_success( id, reason ){
	var id, reason;
	if(!reason){
		reason = "-";
	}
	set_kb_item( name: "docker/docker_test/success/" + id, value: reason );
	docker_success_tests++;
}
func docker_test_set_skipped( id, reason ){
	var id, reason;
	if(!reason){
		reason = "-";
	}
	set_kb_item( name: "docker/docker_test/skipped/" + id, value: reason );
	docker_skipped_tests++;
}
func docker_test_set_error( id, reason ){
	var id, reason;
	if(!reason){
		reason = "-";
	}
	set_kb_item( name: "docker/docker_test/error/" + id, value: reason );
	docker_error_tests++;
}
func docker_run_cmd( cmd ){
	var cmd;
	var buf;
	cmd = "LANG=C; LC_ALL=C; " + cmd;
	buf = ssh_cmd_exec( cmd: cmd );
	return chomp( buf );
}
func get_docker_test_data( id ){
	var id;
	var data;
	data = docker_test[id];
	return data;
}
func docker_test_is_enabled( id  ){
	if(!id){
		return FALSE;
	}
	if(in_array( array: docker_activated_tests, search: id )){
		return TRUE;
	}
	set_kb_item( name: "docker/docker_test/disabled", value: id );
	return FALSE;
}
func docker_systemd_file( file ){
	var file;
	var value, df, systemd;
	if(!file){
		return;
	}
	value = docker_run_cmd( cmd: "systemctl show -p FragmentPath " + file );
	if(!value || !IsMatchRegexp( value, "^FragmentPath=/" ) || !ContainsString( value, file )){
		return FALSE;
	}
	df = split( buffer: value, sep: "=", keep: FALSE );
	if(ContainsString( df[1], file )){
		systemd = docker_run_cmd( cmd: "stat -c %F " + df[1] );
		if(ContainsString( systemd, "regular file" )){
			return df[1];
		}
	}
	return FALSE;
}
func docker_inspect( inspect ){
	var inspect;
	var docker_inspect_base, value;
	if(!inspect){
		return 2;
	}
	docker_inspect_base = "docker inspect --format 'id={{ printf " + "\"%.12s\"" + " $.Id }}, Name={{ printf " + "\"%-25.40s\"" + " .Name }}- ";
	value = docker_run_cmd( cmd: docker_inspect_base + inspect + "' " + join( list: docker_running_containers_short_id_list(), sep: " " ) + "; echo \"exit=$?\"" );
	if(ContainsString( value, "exit=1" ) && ContainsString( value, "Id is not a field of struct type" )){
		value = docker_run_cmd( cmd: str_replace( string: docker_inspect_base, find: "$.Id", replace: "$.ID" ) + inspect + "' " + join( list: docker_running_containers_short_id_list(), sep: " " ) + "; echo \"exit=$?\"" );
	}
	if(!ContainsString( value, "exit=0" )){
		return make_list( "-1",
			 "Docker Inspect Error: " + value );
	}
	value = str_replace( string: value, find: "=[]", replace: "=" );
	value = str_replace( string: value, find: "=<no value>", replace: "=" );
	value = str_replace( string: value, find: "=<nil>", replace: "=" );
	value = str_replace( string: value, find: "=<null>", replace: "=" );
	value = str_replace( string: value, find: "=null", replace: "=" );
	value = str_replace( string: value, find: "=00", replace: "=0" );
	value = ereg_replace( string: value, pattern: "exit=[0-9]+", replace: "" );
	return make_list( "0",
		 value );
}
func docker_running_containers_short_id_list(  ){
	var ret, docker_running_containers, _container;
	ret = make_list();
	if(!docker_running_containers = get_docker_running_containers()){
		return ret;
	}
	for _container in docker_running_containers {
		ret = make_list( ret,
			 docker_truncate_id( _container["id"] ) );
	}
	return ret;
}
func docker_port_values(  ){
	var ret, docker_running_containers, _container;
	var ports, value, v, i;
	ret = make_array();
	if(!docker_running_containers = get_docker_running_containers()){
		return ret;
	}
	for _container in docker_running_containers {
		ports = "";
		value = docker_run_cmd( cmd: "docker port " + _container["id"] );
		if(!value){
			continue;
		}
		v = split( value );
		if(!v){
			continue;
		}
		for(i = 0;i < max_index( v );i++){
			if(v[i]){
				ports += chomp( v[i] ) + ", ";
			}
		}
		ret[_container["id"]] = ports;
	}
	return ret;
}
func docker_read_cmd_line(  ){
	var pid, short2long, data, _s2l;
	pid = get_docker_pid();
	if(!pid){
		return;
	}
	short2long = make_array( "-D", "--debug", "-H", "--host", "-e", "--exec-driver", "-l", "--log-level", "-v", "--version" );
	data = docker_run_cmd( cmd: "tr '\\0' ' ' < /proc/" + pid + "/cmdline" );
	for _s2l in keys( short2long ) {
		data = str_replace( string: data, find: _s2l, replace: short2long[_s2l] );
	}
	return data;
}

