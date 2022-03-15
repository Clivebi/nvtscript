OPT_WILL = 0xfb;
OPT_WONT = 0xfc;
OPT_DO = 0xfd;
OPT_DONT = 0xfe;
OPT_SUBOPT = 0xfa;
OPT_ENDSUBOPT = 0xf0;
var _telnet_is_broken_array;
_telnet_is_broken_array = make_array();
__no_telnet = make_list( "<<<check_mk>>>",
	 "\\\\check_mk\\.ini",
	 "<<<uptime>>>",
	 "<<<services>>>",
	 "<<<mem>>>",
	 "Check_MK_Agent",
	 " stopped/demand ",
	 " running/auto ",
	 " stopped/disabled ",
	 "NOTIC: iSCSI:",
	 "INFOR: iSCSI:",
	 "ERROR: iSCSI:",
	 "Press Enter for Setup Mode",
	 "^ATQ",
	 "HSQLDB JDBC Network Listener",
	 "^OK MPD",
	 "^IOR:",
	 "Host.*is not allowed to connect to this (MySQL|MariaDB) server",
	 "Host.*is blocked.*mysqladmin flush-hosts",
	 "mysql_native_password",
	 "Where are you?",
	 "DOCTYPE GANGLIA_XML",
	 "^Asterisk Call Manager",
	 "^w0256",
	 "java\\.rmi\\.MarshalledObject",
	 "<\\?xml version=",
	 "\\-nthreads",
	 "NServer:",
	 "^ERROR :Closing Link:.*Throttled: Reconnecting too fast",
	 "^:.*NOTICE (Auth|AUTH).*Looking up your hostname",
	 "^TDMM",
	 "^UDMM",
	 "\\+HELLO v([0-9.]+) \\$Name:",
	 "^ getnameinfo: Temporary failure in name resolution $",
	 "Welcome to the TeamSpeak 3 ServerQuery interface",
	 "500 OOPS: could not bind listening IPv4 socket",
	 "^ncacn_http/1\\.0",
	 "^220 .*FTP [Ss]erver .*ready",
	 "^220 .*Ready for user login\\.",
	 "^220 Service ready",
	 "^RFB 00[0-9]\\.00[0-9]",
	 "^Event trace client start:",
	 "\\(Eggdrop v.* Eggheads\\)" );
func telnet_get_banner( port, timeout ){
	var port, timeout;
	var banner, soc;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#telnet_get_banner" );
		return FALSE;
	}
	banner = get_kb_item( "telnet/banner/" + port );
	if(banner){
		return ( banner );
	}
	if(!get_port_state( port )){
		return NULL;
	}
	if(telnet_get_is_marked_broken( port: port )){
		return NULL;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		telnet_set_is_marked_broken( port: port );
		return NULL;
	}
	banner = telnet_negotiate( socket: soc, timeout: timeout );
	if(!banner){
		close( soc );
		telnet_set_is_marked_broken( port: port );
		return NULL;
	}
	if(!telnet_verify_banner( data: banner )){
		close( soc );
		return NULL;
	}
	telnet_set_banner( port: port, banner: banner );
	telnet_close_socket( socket: soc, data: banner );
	return banner;
}
func telnet_negotiate( socket, timeout ){
	var socket, timeout;
	var counter, s, buf, prev, counter2;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#telnet_negotiate" );
		return NULL;
	}
	counter = 0;
	if(!timeout || timeout < 0){
		timeout = 3;
	}
	for(;TRUE;){
		s = recv( socket: socket, length: 1, timeout: timeout );
		if(!strlen( s )){
			break;
		}
		if( ord( s[0] ) != 0xff ){
			buf += s;
		}
		else {
			counter++;
			s = recv( socket: socket, length: 2 );
			if( ord( s[0] ) == OPT_DO ){
				send( socket: socket, data: raw_string( 0xff, OPT_WONT ) + s[1] );
			}
			else {
				if( ord( s[0] ) == OPT_WILL ){
					send( socket: socket, data: raw_string( 0xff, OPT_DONT ) + s[1] );
				}
				else {
					if(ord( s[0] ) == OPT_SUBOPT){
						prev = recv( socket: socket, length: 1 );
						counter2 = 0;
						for(;ord( prev ) != 0xff && ord( s[0] ) != OPT_ENDSUBOPT;){
							prev = s;
							s = recv( socket: socket, length: 1, timeout: 0 );
							if(!strlen( s )){
								return buf;
							}
							counter2++;
							if(counter2 >= 100){
								return buf;
							}
						}
					}
				}
			}
		}
		if(counter >= 100 || strlen( buf ) >= 4096){
			break;
		}
	}
	return buf;
}
func telnet_set_banner( port, banner ){
	var port, banner;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#telnet_set_banner" );
		return NULL;
	}
	if(!banner){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#banner#-#telnet_set_banner" );
		return NULL;
	}
	replace_kb_item( name: "telnet/banner/" + port, value: str_replace( find: raw_string( 0 ), replace: "", string: banner ) );
	return TRUE;
}
func telnet_get_port( default, nodefault, ignore_broken, ignore_unscanned ){
	var default, nodefault, ignore_broken, ignore_unscanned;
	var port;
	if(!default && !nodefault){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#telnet_get_port" );
		exit( 0 );
	}
	port = get_kb_item( "Services/telnet" );
	if(port){
		default = port;
	}
	if(!default){
		exit( 0 );
	}
	if(!ignore_unscanned && !get_port_state( default )){
		exit( 0 );
	}
	if(port_is_marked_fragile( port: default )){
		exit( 0 );
	}
	if(!ignore_broken && telnet_get_is_marked_broken( port: default )){
		exit( 0 );
	}
	return default;
}
func telnet_get_ports( default_port_list=make_list( 23,
		 992 ), ignore_broken=nil, ignore_unscanned=nil ){
	var default_port_list, ignore_broken, ignore_unscanned;
	var final_port_list, check_port_list, default_ports, num_ports, ports, _port;
	final_port_list = make_list();
	check_port_list = make_list();
	default_ports = make_list( 23,
		 992 );
	num_ports = 0;
	ports = get_kb_list( "Services/telnet" );
	if(ports && NASLTypeof( ports ) == "array"){
		for _port in ports {
			num_ports++;
			check_port_list = make_list( check_port_list,
				 _port );
		}
	}
	if(num_ports == 0){
		if( default_port_list && NASLTypeof( default_port_list ) == "array" ) {
			check_port_list = default_port_list;
		}
		else {
			check_port_list = default_ports;
		}
	}
	for _port in check_port_list {
		if(!ignore_unscanned && !get_port_state( _port )){
			continue;
		}
		if(port_is_marked_fragile( port: _port )){
			continue;
		}
		if(!ignore_broken && telnet_get_is_marked_broken( port: _port )){
			continue;
		}
		final_port_list = make_list( final_port_list,
			 _port );
	}
	return final_port_list;
}
func telnet_close_socket( socket, data ){
	var socket, data;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#telnet_close_socket" );
		return;
	}
	if( ( ContainsString( data, "Sollae Systems" ) && ( IsMatchRegexp( data, "lsh>$" ) || IsMatchRegexp( data, "msh>$" ) || ContainsString( data, "password" ) ) ) || ContainsString( data, "Please type \"menu\" for the MENU system," ) || ContainsString( data, "or \"?\" for help, or \"/\" for current settings" ) || ( ContainsString( data, "BusyBox" ) && ContainsString( data, "Built-in shell" ) ) || ContainsString( data, "Enter 'help' for a list of built-in commands." ) || ContainsString( data, "Welcome to NetLinx" ) || ContainsString( data, "Local devices for system" ) || IsMatchRegexp( data, "^->" ) || ContainsString( data, "Welcome to HiLinux." ) ){
		send( socket: socket, data: "exit\r\n" );
	}
	else {
		if( ContainsString( data, "X - Exit Telnet Session" ) ){
			send( socket: socket, data: "x\r\n" );
		}
		else {
			if( ContainsString( data, "<CTRL>" ) && ContainsString( data, "X-Logout" ) ){
				send( socket: socket, data: raw_string( 0x18 ) );
			}
			else {
				if(ContainsString( data, "Huawei Versatile Routing Platform Software" ) || ContainsString( data, "VRP (R) software" )){
					send( socket: socket, data: "quit\r\n" );
				}
			}
		}
	}
	close( socket );
}
func telnet_get_is_marked_broken( port ){
	var port;
	var marked_broken_list, marked_broken;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#telnet_get_is_marked_broken" );
		return NULL;
	}
	if(!isnull( _telnet_is_broken_array[port] )){
		if( _telnet_is_broken_array[port] ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	marked_broken = get_kb_item( "telnet/" + port + "/is_broken" );
	if( marked_broken ){
		_telnet_is_broken_array[port] = TRUE;
	}
	else {
		_telnet_is_broken_array[port] = FALSE;
		marked_broken = FALSE;
	}
	return marked_broken;
}
func telnet_set_is_marked_broken( port ){
	var port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#telnet_set_is_marked_broken" );
		return NULL;
	}
	set_kb_item( name: "telnet/is_broken", value: TRUE );
	set_kb_item( name: "telnet/" + port + "/is_broken", value: TRUE );
	_telnet_is_broken_array[port] = TRUE;
	return TRUE;
}
func telnet_verify_banner( data ){
	var data;
	var _nt;
	data = chomp( data );
	if(!data){
		return FALSE;
	}
	if(strlen( data ) < 4){
		return FALSE;
	}
	data = bin2string( ddata: data, noprint_replacement: " " );
	if(!data || IsMatchRegexp( data, "^[ \r\n]*$" )){
		return FALSE;
	}
	for _nt in __no_telnet {
		if(egrep( pattern: _nt, string: data )){
			return FALSE;
		}
	}
	return TRUE;
}
func telnet_has_login_prompt( data ){
	var data;
	if(!telnet_verify_banner( data: data )){
		return FALSE;
	}
	if(!IsMatchRegexp( data, "(Pocket CMD.+\\\\>|Kernel|login|password|user ?name|user|press enter.+setup mode|polycom command shell|welcome to viewstation|hi, my name is.+here is what i know about myself|you are logged in|management console.+sollae systems|lsh>|Welcome\\. Type <return>, enter password at # prompt|BusyBox|list of built-in commands|Welcome to NetLinx) ?:?" )){
		return FALSE;
	}
	return TRUE;
}

