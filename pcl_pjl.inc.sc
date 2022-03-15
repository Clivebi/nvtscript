func pcl_pjl_get_detect_requests( vt_strings ){
	var vt_strings;
	var final_reqs, reqs, req;
	final_reqs = make_array();
	reqs = make_list( "@PJL INFO ID",
		 "@PJL INFO STATUS",
		 "@PJL INFO LOG",
		 "@PJL INFO SUPPLIES",
		 "@PJL INFO PRODINFO",
		 "@PJL USTATUS DEVICE",
		 "@PJL ECHO" + vt_strings["default"] );
	for _req in reqs {
		final_reqs["\x1b%-12345X" + _req + "\r\n\x1b%-12345X\r\n"] = _req + "\r\n";
	}
	final_reqs[raw_string( 0x1B ) + "*s1M"] = "PCL";
	final_reqs[raw_string( 0x1B ) + "*s#X"] = "PCL";
	return final_reqs;
}
func pcl_pjl_register_all_ports( ports ){
	var ports;
	var _port;
	if(isnull( ports ) || NASLTypeof( ports ) != "array"){
		ports = pcl_pjl_get_default_ports();
	}
	for _port in ports {
		if(get_port_state( _port )){
			service_register( port: _port, proto: "hp-pjl" );
			service_register( port: _port, proto: "fragile_port" );
			replace_kb_item( name: "BannerHex/" + _port, value: "aeaeaeaeae" );
			replace_kb_item( name: "Banner/" + _port, value: "ignore-this-banner" );
		}
	}
	return;
}
func pcl_pjl_get_default_ports(  ){
	var ports;
	ports = make_list( 2000,
		 2501,
		 9100,
		 9101,
		 9102,
		 9103,
		 9104,
		 9105,
		 9106,
		 9107,
		 9112,
		 9113,
		 9114,
		 9115,
		 9116,
		 9200,
		 10001 );
	return ports;
}
func pcl_pjl_get_default_ports_string(  ){
	var ports, _port, ret;
	ports = pcl_pjl_get_default_ports();
	if(isnull( ports ) || NASLTypeof( ports ) != "array"){
		return NULL;
	}
	for _port in ports {
		if( !ret ) {
			ret = _port;
		}
		else {
			ret += "," + _port;
		}
	}
	return ret;
}

