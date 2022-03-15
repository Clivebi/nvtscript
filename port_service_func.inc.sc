var _port_service_func_debug;
_port_service_func_debug = 0;
func port_is_marked_fragile( port ){
	var port;
	var fragile_ports, _fragile_port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#port_is_marked_fragile" );
		return;
	}
	fragile_ports = get_kb_list( "Services/fragile_port" );
	if(!fragile_ports){
		return;
	}
	for _fragile_port in fragile_ports {
		if(port == _fragile_port){
			return TRUE;
		}
	}
	return;
}
func tcp_get_all_port(  ){
	var port;
	port = get_kb_item( "TCP/PORTS" );
	if(!port){
		exit( 0 );
	}
	if(port_is_marked_fragile( port: port )){
		exit( 0 );
	}
	if(!get_port_state( port )){
		exit( 0 );
	}
	return port;
}
func tcp_get_all_ports(  ){
	var ports, kb_ports, _port;
	ports = make_list();
	kb_ports = get_kb_list( "TCP/PORTS" );
	for _port in kb_ports {
		if(port_is_marked_fragile( port: _port )){
			continue;
		}
		if(!get_port_state( _port )){
			continue;
		}
		ports = make_list( ports,
			 _port );
	}
	return ports;
}
func tcp_get_first_open_port( exit_no_found_port ){
	var exit_no_found_port;
	var ports;
	if(isnull( exit_no_found_port )){
		exit_no_found_port = TRUE;
	}
	ports = tcp_get_all_ports();
	if( isnull( ports[0] ) ){
		if( exit_no_found_port ) {
			exit( 0 );
		}
		else {
			return NULL;
		}
	}
	else {
		return ports[0];
	}
}
func udp_get_all_port(  ){
	var port;
	port = get_kb_item( "UDP/PORTS" );
	if(!port){
		exit( 0 );
	}
	if(!get_udp_port_state( port )){
		exit( 0 );
	}
	return port;
}
func udp_get_all_ports(  ){
	var ports, kb_ports, _port;
	ports = make_list();
	kb_ports = get_kb_list( "UDP/PORTS" );
	for _port in kb_ports {
		if(!get_udp_port_state( _port )){
			continue;
		}
		ports = make_list( ports,
			 _port );
	}
	return ports;
}
func unknownservice_get_ports( default_port_list, nodefault, ipproto ){
	var default_port_list, nodefault, ipproto;
	var __port_list, udp, port_list, _default, _port_list, _port;
	__port_list = make_list();
	if(!nodefault){
		if(!default_port_list){
			set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default_port_list#-#unknownservice_get_ports" );
			return __port_list;
		}
		if(!is_array( default_port_list )){
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#unknownservice_get_ports: No list passed in 'default_port_list' parameter" );
			return __port_list;
		}
	}
	if(!default_port_list || !is_array( default_port_list )){
		default_port_list = __port_list;
	}
	if(!ipproto){
		ipproto = "tcp";
	}
	if( ipproto == "tcp" ){
		udp = FALSE;
		port_list = get_kb_list( "Services/unknown" );
	}
	else {
		if( ipproto == "udp" ){
			udp = TRUE;
			if( get_kb_item( "global_settings/non-default_udp_service_discovery" ) ){
				port_list = get_kb_list( "Services/udp/unknown" );
			}
			else {
				port_list = default_port_list;
			}
		}
		else {
			udp = FALSE;
			port_list = get_kb_list( "Services/" + ipproto + "/unknown" );
		}
	}
	if( port_list ){
		_port_list = port_list;
		for _default in default_port_list {
			if(!in_array( search: _default, array: port_list, part_match: FALSE )){
				_port_list = make_list( _default,
					 _port_list );
			}
		}
	}
	else {
		_port_list = default_port_list;
	}
	for _port in _port_list {
		if(!udp){
			if(_port == 139){
				continue;
			}
			if(port_is_marked_fragile( port: _port )){
				continue;
			}
		}
		if(!in_array( search: _port, array: default_port_list, part_match: FALSE )){
			if(!service_is_unknown( port: _port, ipproto: ipproto )){
				continue;
			}
		}
		if( !udp ){
			if(!get_port_state( _port )){
				continue;
			}
		}
		else {
			if(!get_udp_port_state( _port )){
				continue;
			}
		}
		__port_list = make_list( __port_list,
			 _port );
	}
	return __port_list;
}
func unknownservice_get_port( default, nodefault, ipproto ){
	var default, nodefault, ipproto;
	var udp, _port, port;
	if(!nodefault && !default){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#unknownservice_get_port" );
		exit( 0 );
	}
	if(!ipproto){
		ipproto = "tcp";
	}
	if( ipproto == "tcp" ){
		udp = FALSE;
		port = get_kb_item( "Services/unknown" );
	}
	else {
		if( ipproto == "udp" ){
			udp = TRUE;
			if( get_kb_item( "global_settings/non-default_udp_service_discovery" ) ){
				port = get_kb_item( "Services/udp/unknown" );
			}
			else {
				port = default;
			}
		}
		else {
			udp = FALSE;
			port = get_kb_item( "Services/" + ipproto + "/unknown" );
		}
	}
	if( port ) {
		_port = port;
	}
	else {
		_port = default;
	}
	if(!_port){
		exit( 0 );
	}
	if(!udp){
		if(_port == 139){
			exit( 0 );
		}
		if(port_is_marked_fragile( port: _port )){
			exit( 0 );
		}
	}
	if(_port != default){
		if(!service_is_unknown( port: _port, ipproto: ipproto )){
			exit( 0 );
		}
	}
	if( !udp ){
		if(!get_port_state( _port )){
			exit( 0 );
		}
	}
	else {
		if(!get_udp_port_state( _port )){
			exit( 0 );
		}
	}
	return _port;
}
func unknown_banner_get( port, ipproto, dontfetch ){
	var port, ipproto, dontfetch;
	var tcp, sb, sbH, banner, soc, _p, bannerHex;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#unknown_banner_get" );
		return;
	}
	if(!ipproto){
		ipproto = "tcp";
	}
	if( ipproto == "tcp" ) {
		tcp = TRUE;
	}
	else {
		tcp = FALSE;
	}
	if( tcp ){
		sb = strcat( "unknown/banner/", port );
		sbH = strcat( "unknown/bannerHex/", port );
	}
	else {
		sb = strcat( "unknown/banner/", ipproto, "/", port );
		sbH = strcat( "unknown/bannerHex/", ipproto, "/", port );
	}
	banner = get_kb_item( sbH );
	if(banner){
		return hex2raw( s: banner );
	}
	banner = get_kb_item( sb );
	if(banner){
		return banner;
	}
	banner = get_kb_item( "BannerHex/" + port );
	if(banner){
		return ( hex2raw( s: banner ) );
	}
	banner = get_kb_item( "Banner/" + port );
	if(banner){
		return ( banner );
	}
	for _p in make_list( "spontaneous",
		 "get_http",
		 "help",
		 "xml",
		 "json",
		 "sip",
		 "bin" ) {
		banner = get_kb_item( "FindService/" + ipproto + "/" + port + "/" + _p );
		bannerHex = get_kb_item( "FindService/" + ipproto + "/" + port + "/" + _p + "Hex" );
		if(banner || bannerHex){
			if( strlen( bannerHex ) > 2 * strlen( banner ) ) {
				return hex2raw( s: bannerHex );
			}
			else {
				return ( banner );
			}
		}
	}
	if(dontfetch){
		return ( NULL );
	}
	if(!tcp){
		return ( NULL );
	}
	if(!get_port_state( port )){
		return ( NULL );
	}
	soc = open_sock_tcp( port );
	if(!soc){
		return ( NULL );
	}
	banner = recv( socket: soc, length: 2048 );
	close( soc );
	if(banner){
		replace_kb_item( name: sb, value: banner );
		if(ContainsString( sb, "\0" )){
			replace_kb_item( name: sbH, value: hexstr( banner ) );
		}
	}
	return ( banner );
}
func unknown_banner_set( port, banner, ipproto ){
	var sb, port, banner, ipproto;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#unknown_banner_set" );
	}
	if( !ipproto || ipproto == "tcp" ) {
		sb = NASLString( "unknown/banner/", port );
	}
	else {
		sb = strcat( "unknown/banner/", ipproto, "/", port );
	}
	set_kb_item( name: sb, value: banner );
	if(ContainsString( banner, "\0" )){
		if( !ipproto || ipproto == "tcp" ) {
			sb = NASLString( "unknown/bannerHex/", port );
		}
		else {
			sb = strcat( "unknown/bannerHex/", ipproto, "/", port );
		}
		set_kb_item( name: sb, value: hexstr( banner ) );
	}
}
func unknown_banner_report( port, ipproto ){
	var port, ipproto;
	var tcp, _method, banner;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#unknown_banner_report" );
		return NULL;
	}
	if(!ipproto){
		ipproto = "tcp";
	}
	if( ipproto == "tcp" ) {
		tcp = TRUE;
	}
	else {
		tcp = FALSE;
	}
	for _method in make_list( "spontaneousHex",
		 "spontaneous",
		 "get_httpHex",
		 "get_http",
		 "helpHex",
		 "help",
		 "xmlHex",
		 "xml",
		 "jsonHex",
		 "json",
		 "sipHex",
		 "sip",
		 "binHex",
		 "bin" ) {
		banner = get_kb_item( "FindService/" + ipproto + "/" + port + "/" + _method );
		if(banner && strlen( banner ) >= 3){
			return ( make_list( _method,
				 banner ) );
		}
	}
	if( tcp ){
		banner = get_kb_item( "unknown/bannerHex/" + port );
		if(banner){
			return ( make_list( "'unknown/bannerHex/' KB entry",
				 banner ) );
		}
		banner = get_kb_item( "unknown/banner/" + port );
		if(banner){
			return ( make_list( "'unknown/banner/' KB entry",
				 banner ) );
		}
	}
	else {
		banner = get_kb_item( "unknown/bannerHex/" + ipproto + "/" + port );
		if(banner){
			return ( make_list( "'unknown/bannerHex/" + ipproto + "/' KB entry",
				 banner ) );
		}
		banner = get_kb_item( "unknown/banner/" + ipproto + "/" + port );
		if(banner){
			return ( make_list( "'unknown/banner/" + ipproto + "/' KB entry",
				 banner ) );
		}
	}
	banner = get_kb_item( "BannerHex/" + port );
	if(banner){
		return ( make_list( "'BannerHex/' KB entry",
			 banner ) );
	}
	banner = get_kb_item( "Banner/" + port );
	if(banner){
		return ( make_list( "'Banner/' KB entry",
			 banner ) );
	}
}
func service_verify( port, ipproto, proto ){
	var port, ipproto, proto;
	var known, _known;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#verify_service" );
		return NULL;
	}
	if(!proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#verify_service" );
		return NULL;
	}
	if(!ipproto){
		ipproto = "tcp";
	}
	known = get_kb_list( "Known/" + ipproto + "/" + port );
	if(!known){
		return FALSE;
	}
	for _known in known {
		if(_known && _known == proto){
			return TRUE;
		}
	}
	return FALSE;
}
func service_get_port( default, nodefault, ipproto, proto, ignore_unscanned ){
	var default, nodefault, ipproto, proto, ignore_unscanned;
	var key, port;
	if(!proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#service_get_port" );
		exit( 0 );
	}
	if(!default && !nodefault){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#service_get_port" );
		exit( 0 );
	}
	if(!ipproto){
		ipproto = "tcp";
	}
	if( ipproto == "tcp" ) {
		key = strcat( "Services/", proto );
	}
	else {
		key = strcat( "Services/", ipproto, "/", proto );
	}
	port = get_kb_item( key );
	if(port){
		return port;
	}
	if(!default){
		exit( 0 );
	}
	port = get_kb_item( "Known/" + ipproto + "/" + default );
	if(port == proto){
		return default;
	}
	if(ipproto == "tcp" && ( get_tcp_port_state( default ) || ignore_unscanned )){
		if(port_is_marked_fragile( port: default )){
			exit( 0 );
		}
		return default;
	}
	if(ipproto == "udp" && ( get_udp_port_state( default ) || ignore_unscanned )){
		return default;
	}
	exit( 0 );
}
func service_get_ports( default_port_list, ipproto, proto, ignore_unscanned ){
	var default_port_list, ipproto, proto, ignore_unscanned;
	var port_list, num_ports, key, ports, _port, _default;
	port_list = make_list();
	if(!proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#service_get_ports" );
		return port_list;
	}
	num_ports = 0;
	if(!ipproto){
		ipproto = "tcp";
	}
	if( ipproto == "tcp" ) {
		key = strcat( "Services/", proto );
	}
	else {
		key = strcat( "Services/", ipproto, "/", proto );
	}
	ports = get_kb_list( key );
	if(ports && NASLTypeof( ports ) == "array"){
		for _port in ports {
			num_ports++;
			port_list = make_list( port_list,
				 _port );
		}
	}
	if(num_ports > 0){
		return port_list;
	}
	if(!default_port_list || NASLTypeof( default_port_list ) != "array"){
		return port_list;
	}
	for _default in default_port_list {
		ports = get_kb_list( "Known/" + ipproto + "/" + _default );
		if(ports && NASLTypeof( ports ) == "array"){
			for _port in keys( ports ) {
				if(ports[_port] == proto){
					num_ports++;
					port_list = make_list( port_list,
						 _default );
				}
			}
		}
	}
	if(num_ports > 0){
		return port_list;
	}
	for _default in default_port_list {
		if(ipproto == "tcp" && ( get_tcp_port_state( _default ) || ignore_unscanned )){
			if(port_is_marked_fragile( port: _default )){
				continue;
			}
			port_list = make_list( port_list,
				 _default );
		}
		if(ipproto == "udp" && ( get_udp_port_state( _default ) || ignore_unscanned )){
			port_list = make_list( port_list,
				 _default );
		}
	}
	return port_list;
}
func service_report( port, svc, banner, message ){
	var port, svc, banner, message;
	var name, a, report;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#service_report" );
	}
	if(!svc){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#svc#-#service_report" );
	}
	svc = tolower( svc );
	if(banner && strlen( banner ) > 0){
		set_kb_item( name: svc + "/banner/" + port, value: banner );
	}
	if( svc == "www" ) {
		name = "web server";
	}
	else {
		if( svc == "proxy" ) {
			name = "web proxy";
		}
		else {
			if( svc == "hylafax-ftp" || svc == "hylafax" ) {
				name = "HylaFAX server";
			}
			else {
				if( svc == "agobot.fo" ) {
					name = "Agobot.fo backdoor";
				}
				else {
					if( svc == "unknown_irc_bot" ) {
						name = "IRC bot";
					}
					else {
						if( svc == "auth" ) {
							name = "identd";
						}
						else {
							if( svc == "workgroupshare" ) {
								name = "WorkgroupShare Server";
							}
							else {
								name = toupper( svc ) + " server";
							}
						}
					}
				}
			}
		}
	}
	a = tolower( name[0] );
	if( a == "a" || a == "e" || a == "i" || a == "o" ) {
		a = "An ";
	}
	else {
		a = "A ";
	}
	report = a + name + " is running on this port.";
	if(!message){
		message = report;
	}
	service_register( port: port, proto: svc, message: message );
	log_message( port: port, data: report );
}
func service_register( port, proto, ipproto, message ){
	var port, proto, ipproto, message;
	var key;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#service_register" );
		return;
	}
	if(!proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#service_register" );
		return;
	}
	if(!ipproto){
		ipproto = "tcp";
	}
	if(!service_is_unknown( port: port, ipproto: ipproto )){
		if(_port_service_func_debug){
			display( get_host_ip(), ": service is already known on port ", ipproto, ":", port, "\\n" );
		}
	}
	if(ipproto != "unknown"){
		key = strcat( "Known/", ipproto, "/", port );
		replace_kb_item( name: key, value: proto );
		if( ipproto == "tcp" ) {
			key = strcat( "Services/", proto );
		}
		else {
			key = strcat( "Services/", ipproto, "/", proto );
		}
		set_kb_item( name: key, value: port );
		service_register_as_host_detail( port: port, proto: ipproto, service: proto, message: message );
	}
	if(_port_service_func_debug){
		display( get_host_ip(), ": service_register: port=", port, ", proto=", proto, "\\n" );
	}
	return;
}
func service_register_as_host_detail( port, proto, service, message ){
	var port, proto, service, message, hd;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#service_register_as_host_detail" );
		return;
	}
	if(!service){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#service#-#service_register_as_host_detail" );
		return;
	}
	if(!proto){
		proto = "tcp";
	}
	hd = port + "," + proto + "," + service;
	if(message){
		hd += "," + message;
	}
	register_host_detail( name: "Services", value: hd, desc: "Service detection (" + get_script_oid() + ")" );
	return;
}
func service_is_unknown( port, ipproto ){
	var port, ipproto;
	var known, _known;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#service_is_unknown" );
		return NULL;
	}
	if(!ipproto){
		ipproto = "tcp";
	}
	known = get_kb_list( "Known/" + ipproto + "/" + port );
	if(!known){
		return TRUE;
	}
	for _known in known {
		if(_known && _known != "unknown"){
			return FALSE;
		}
	}
	return TRUE;
}
func service_is_known( port, ipproto ){
	var port, ipproto;
	var known, _known;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#service_is_known" );
		return NULL;
	}
	if(!ipproto){
		ipproto = "tcp";
	}
	known = get_kb_list( "Known/" + ipproto + "/" + port );
	if(!known){
		return FALSE;
	}
	for _known in known {
		if(_known && _known != "unknown"){
			return TRUE;
		}
	}
	return FALSE;
}

