func pcap_tcp_udp_send_recv( port, srcport, data, proto, debug, pcap_filter, allow_self ){
	var port, srcport, data, proto, debug, pcap_filter;
	var data_size, default_mtu, PCAP_TIMEOUT, ownip, targetip, dstport, IPPROTO, IPV6_VERSION;
	var ip_packet, tcp_or_udp_packet, res;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#pcap_tcp_udp_send_recv" );
		return NULL;
	}
	if(isnull( data )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#pcap_tcp_udp_send_recv" );
		return NULL;
	}
	data_size = strlen( data );
	default_mtu = 1500;
	if(data_size > default_mtu){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#pcap_tcp_udp_send_recv: Size of data passed to the 'data' parameter '" + data_size + "' > '" + default_mtu + "' (Default MTU assumed). This might not work as expected." );
	}
	if(!proto){
		proto = "udp";
	}
	if(!srcport){
		srcport = rand() % ( 65536 - 1024 ) + 1024;
	}
	PCAP_TIMEOUT = 5;
	ownip = this_host();
	targetip = get_host_ip();
	dstport = port;
	if(!allow_self && ownip == targetip){
		if(debug){
			display( "---[ ownip == targetip and 'allow_self' not set to 'TRUE'. Exiting... ]---" );
		}
		return NULL;
	}
	if( proto == "tcp" ){
		if(!pcap_filter){
			pcap_filter = "src host " + targetip + " and dst host " + ownip + " and tcp and tcp src port " + dstport + " and tcp dst port " + srcport;
		}
		IPPROTO = IPPROTO_TCP;
	}
	else {
		if(!pcap_filter){
			pcap_filter = "src host " + targetip + " and dst host " + ownip + " and udp and udp src port " + dstport + " and udp dst port " + srcport;
		}
		IPPROTO = IPPROTO_UDP;
	}
	if(debug){
		display( "---[ Chosen / passed PCAP filter ]---", "\\n", pcap_filter );
	}
	if( TARGET_IS_IPV6() ){
		if( version_is_less( version: OPENVAS_VERSION, test_version: "20.8.0" ) ) {
			IPV6_VERSION = 0x60;
		}
		else {
			IPV6_VERSION = 6;
		}
		ip_packet = forge_ipv6_packet( ip6_v: IPV6_VERSION, ip6_p: IPPROTO, ip6_src: ownip, ip6_dst: targetip, ip6_tc: 0, ip6_fl: 0, ip6_hlim: 64 );
		if(!ip_packet){
			if(debug){
				display( "---[ Failed to craft IPv6 packet ]---" );
			}
			return NULL;
		}
		if(debug){
			display( "---[ Crafted IPv6 packet ]---" );
			dump_ipv6_packet( ip_packet );
		}
		if( proto == "tcp" ){
			tcp_or_udp_packet = forge_tcp_v6_packet( ip6: ip_packet, data: data, th_sport: srcport, th_dport: dstport, th_seq: rand(), th_ack: 0, th_x2: 0, th_off: 5, th_flags: 0, th_win: 0, th_urp: 0, update_ip_len: TRUE );
			if(!tcp_or_udp_packet){
				if(debug){
					display( "---[ Failed to craft TCP packet ]---" );
				}
				return NULL;
			}
			if(debug){
				display( "---[ Crafted TCP packet ]---" );
				dump_tcp_v6_packet( tcp_or_udp_packet );
			}
		}
		else {
			tcp_or_udp_packet = forge_udp_v6_packet( ip6: ip_packet, data: data, uh_sport: srcport, uh_dport: dstport, uh_ulen: strlen( data ) + 8, update_ip6_len: TRUE );
			if(!tcp_or_udp_packet){
				if(debug){
					display( "---[ Failed to craft UDP packet ]---" );
				}
				return NULL;
			}
			if(debug){
				display( "---[ Crafted UDP packet ]---" );
				dump_udp_v6_packet( tcp_or_udp_packet );
			}
		}
		res = send_v6packet( packet: tcp_or_udp_packet, pcap_active: TRUE, pcap_filter: pcap_filter, pcap_timeout: PCAP_TIMEOUT );
		if(!res){
			if(debug){
				display( "---[ No IPv6 packet received (Reasons e.g.: none matching the pcap filter, pcap timeout reached, ...) ]---" );
			}
			return NULL;
		}
		if(debug){
			display( "---[ Received IPv6 packet ]---" );
			dump_ipv6_packet( res );
		}
		if( proto == "tcp" ){
			if(debug){
				display( "---[ Received TCP packet ]---" );
				dump_tcp_v6_packet( res );
			}
			res = get_tcp_v6_element( tcp: res, element: "data" );
		}
		else {
			if(debug){
				display( "---[ Received UDP packet ]---" );
				dump_udp_v6_packet( res );
			}
			res = get_udp_v6_element( udp: res, element: "data" );
		}
	}
	else {
		ip_packet = forge_ip_packet( ip_v: 4, ip_p: IPPROTO, ip_off: 0, ip_src: ownip, ip_dst: targetip, ip_hl: 5, ip_id: rand(), ip_len: strlen( data ) + 20, ip_tos: 0, ip_ttl: 64 );
		if(!ip_packet){
			if(debug){
				display( "---[ Failed to craft IPv4 packet ]---" );
			}
			return NULL;
		}
		if(debug){
			display( "---[ Crafted IPv4 packet ]---" );
			dump_ip_packet( ip_packet );
		}
		if( proto == "tcp" ){
			tcp_or_udp_packet = forge_tcp_packet( ip: ip_packet, data: data, th_sport: srcport, th_dport: dstport, th_ack: 0, th_flags: 0, th_off: 5, th_seq: rand(), th_urp: 0, th_win: 0, th_x2: 0, update_ip_len: TRUE );
			if(!tcp_or_udp_packet){
				if(debug){
					display( "---[ Failed to craft TCP packet ]---" );
				}
				return NULL;
			}
			if(debug){
				display( "---[ Crafted TCP packet ]---" );
				dump_tcp_packet( tcp_or_udp_packet );
			}
		}
		else {
			tcp_or_udp_packet = forge_udp_packet( ip: ip_packet, data: data, uh_sport: srcport, uh_dport: dstport, uh_ulen: strlen( data ) + 8, update_ip_len: TRUE );
			if(!tcp_or_udp_packet){
				if(debug){
					display( "---[ Failed to craft UDP packet ]---" );
				}
				return NULL;
			}
			if(debug){
				display( "---[ Crafted UDP packet ]---" );
				dump_udp_packet( tcp_or_udp_packet );
			}
		}
		res = send_packet( packet: tcp_or_udp_packet, pcap_active: TRUE, pcap_filter: pcap_filter, pcap_timeout: PCAP_TIMEOUT );
		if(!res){
			if(debug){
				display( "---[ No IPv4 packet received (Reasons e.g.: none matching the pcap filter, pcap timeout reached, ...) ]---" );
			}
			return NULL;
		}
		if(debug){
			display( "---[ Received IPv4 packet ]---" );
			dump_ip_packet( res );
		}
		if( proto == "tcp" ){
			if(debug){
				display( "---[ Received TCP packet ]---" );
				dump_tcp_packet( res );
			}
			res = get_tcp_element( tcp: res, element: "data" );
		}
		else {
			if(debug){
				display( "---[ Received UDP packet ]---" );
				dump_udp_packet( res );
			}
			res = get_udp_element( udp: res, element: "data" );
		}
	}
	if(!res){
		if(debug){
			display( "---[ Failed to extract 'data' element from received " + toupper( proto ) + " packet ]---" );
		}
		return NULL;
	}
	if(debug){
		display( "---[ Extracted 'data' element from received " + toupper( proto ) + " packet ]---", "\\n", hexdump( ddata: res ) );
	}
	return res;
}

