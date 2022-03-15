func is_private_addr( addr ){
	var addr;
	var all_addr_private, all_addr_public, network_type, a;
	all_addr_private = FALSE;
	all_addr_public = FALSE;
	network_type = get_kb_item( "global_settings/network_type" );
	if(network_type){
		if( ContainsString( network_type, "Private LAN" ) ) {
			all_addr_private = TRUE;
		}
		else {
			if(ContainsString( network_type, "Internet" ) || ContainsString( network_type, "Public LAN" )){
				all_addr_public = TRUE;
			}
		}
	}
	if(all_addr_private || islocalhost()){
		return TRUE;
	}
	if(all_addr_public && !islocalhost()){
		return FALSE;
	}
	if( !addr ){
		a = get_host_ip();
	}
	else {
		a = addr;
		if(!IsMatchRegexp( a, "^[0-9a-z]+:" ) && !IsMatchRegexp( a, "^0*[0-9]+\\." )){
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#is_private_addr: Invalid IPv4/IPv6 address passed to 'addr' parameter: " + addr );
			return NULL;
		}
	}
	if( ContainsString( a, ":" ) ){
		if(IsMatchRegexp( a, "^f[cd][0-9a-f]+:" )){
			return TRUE;
		}
	}
	else {
		if(IsMatchRegexp( a, "^0*(127|10)\\.[0-9]+\\.[0-9]+\\.[0-9]+" )){
			return TRUE;
		}
		if(IsMatchRegexp( a, "^0*(192\\.0*168|169\\.0*254)\\.[0-9]+\\.[0-9]+" )){
			return TRUE;
		}
		if(IsMatchRegexp( a, "^0*172\\.0*(1[6-9]|2[0-9]|3[01])\\.[0-9]+\\.[0-9]+" )){
			return TRUE;
		}
		if(IsMatchRegexp( a, "^0*192\\.0*0\\.0*2\\.[0-9]+" )){
			return TRUE;
		}
		if(IsMatchRegexp( a, "^0*192\\.0*1[89]\\.[0-9]+\\.[0-9]+" )){
			return TRUE;
		}
	}
	return FALSE;
}
func is_public_addr( addr ){
	var addr;
	if(islocalhost()){
		return FALSE;
	}
	if(islocalnet() && !is_private_addr( addr: addr )){
		return TRUE;
	}
	if(is_private_addr( addr: addr )){
		return FALSE;
	}
	if(!is_private_addr( addr: addr )){
		return TRUE;
	}
	return FALSE;
}
func test_udp_port( port, data, retries ){
	var ip, udp, srcaddr, dstaddr, srcport, r, f, i, n, len, icmp, sp, dp, port, data, retries;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#test_udp_port" );
	}
	if( retries <= 0 ){
		n = 6;
	}
	else {
		n = retries;
	}
	if(isnull( data )){
		data = "";
	}
	for(i = 0;i < n;i++){
		srcaddr = this_host();
		dstaddr = get_host_ip();
		srcport = 1024 + rand() % 64512;
		ip = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_len: 20, ip_id: 0, ip_p: IPPROTO_UDP, ip_ttl: 255, ip_off: 0, ip_src: srcaddr, ip_dst: dstaddr );
		udp = forge_udp_packet( ip: ip, uh_sport: srcport, uh_dport: port, uh_ulen: 8 + strlen( data ), data: data );
		f = strcat( "src host ", dstaddr, " and dst host ", srcaddr, " and ( (udp and src port ", port, " and dst port ", srcport, ") or (", " icmp and icmp[0] = 3 and icmp[1] = 3))" );
		r = send_packet( packet: udp, pcap_timeout: 1, pcap_active: TRUE, pcap_filter: f );
		if(r){
			if( ord( r[9] ) == 17 ){
				return 2;
			}
			else {
				len = ( ord( r[0] ) & 0xF );
				len *= 4;
				icmp = substr( r, len );
				ip = substr( icmp, 8 );
				len = ( ord( ip[0] ) & 0xF );
				len *= 4;
				udp = substr( ip, len );
				sp = ord( udp[0] ) * 256 + ord( udp[1] );
				dp = ord( udp[2] ) * 256 + ord( udp[3] );
				if(srcport == sp && port == dp){
					return 0;
				}
			}
		}
	}
	return 1;
}
func ip_checksum( data ){
	var sum, i, n, data;
	if(isnull( data )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#ip_checksum" );
	}
	n = strlen( data );
	sum = 0;
	for(i = 0;i < n - 1;i += 2){
		sum = sum + ord( data[i] ) * 256 + ord( data[i + 1] );
	}
	if(i < n){
		sum += ord( data[i] );
	}
	sum = ( sum >>> 16 ) + ( sum & 0xffff );
	sum += ( sum >>> 16 );
	sum = ( ~sum ) & 0xFFFF;
	return raw_string( sum % 256, sum / 256 );
}
func ms_since_midnight(  ){
	var s;
	s = unixtime();
	s %= 86400;
	return 1000 * s;
}
func htonl( n ){
	var i, j, s, n;
	if(isnull( n )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#n#-#htonl" );
	}
	j = n;
	for(i = 0;i < 4;i++){
		s[i] = j & 0xFF;
		j >>>= 8;
	}
	return raw_string( s[3], s[2], s[1], s[0] );
}
func htons( n ){
	var n;
	if(isnull( n )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#n#-#htons" );
	}
	return raw_string( ( n >>> 8 ) & 0xFF, n & 0xFF );
}
func ntohl( n ){
	var n;
	if(!n){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#n#-#ntohl" );
	}
	if(strlen( n ) != 4){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ntohl: invalid parameter / length (should be 4)" );
		return;
	}
	return ( ord( n[0] ) << 24 ) | ( ord( n[1] ) << 16 ) | ( ord( n[2] ) << 8 ) | ord( n[3] );
}
func check_udp_port_status( dport ){
	var dport, sport, ip_pkt, udp_pkt, filter, res;
	if(!dport){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#dport#-#check_udp_port_status" );
	}
	sport = rand() % 64512 + 1024;
	ip_pkt = forge_ip_packet( ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20, ip_id: 31337, ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP, ip_src: this_host() );
	udp_pkt = forge_udp_packet( ip: ip_pkt, uh_sport: sport, uh_dport: dport, uh_ulen: 8 );
	filter = NASLString( "src host ", get_host_ip(), " and dst host ", this_host(), " and icmp and (icmp[0] == 3 and icmp[1] == 3 and icmp[28:2]==", sport, " and icmp[30:2]==", dport, ")" );
	res = send_packet( packet: udp_pkt, pcap_active: TRUE, pcap_filter: filter );
	if( res != NULL ){
		return FALSE;
	}
	else {
		return TRUE;
	}
}
func is_radius_alive( port ){
	var port;
	var vt_strings, username, data, soc, buf;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#is_radius_alive" );
		return NULL;
	}
	vt_strings = get_vt_strings();
	username = vt_strings["default"];
	data = raw_string( 0x40, 0xfa, 0xb3, 0x17, 0x23, 0xfd, 0xe5, 0x7f, 0x4a, 0x02, 0x74, 0x55, 0x15, 0x0c, 0x45, 0xeb ) + raw_string( 0x01, ( strlen( username ) + 2 ) ) + username + raw_string( 0x02, 0x12, 0xfa, 0x4d, 0xb1, 0x43, 0x69, 0xd5, 0x69, 0x8b, 0x1f, 0x30, 0xea, 0xf4, 0x54, 0x45, 0x1e, 0x70, 0x04, 0x06, 0x05, 0x06, 0x00, 0x00, 0x15, 0x38 );
	data = raw_string( 0x01, 0xbe, 0x00, ( strlen( data ) + 4 ) ) + data;
	soc = open_sock_udp( port );
	if(soc){
		send( socket: soc, data: data );
		buf = recv( socket: soc, length: 4096 );
		close( soc );
		if(buf && ord( buf[0] ) == 3){
			return TRUE;
		}
	}
	return FALSE;
}
func verify_register_mac_address( data, desc, prefix_string ){
	var data, des, prefix_string;
	var mac, final_mac;
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#verify_register_mac_address" );
		return NULL;
	}
	if(!desc){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#desc#-#verify_register_mac_address" );
		return NULL;
	}
	if(strlen( data ) < 14){
		return FALSE;
	}
	if(mac = eregmatch( string: data, pattern: prefix_string + "(([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})|([0-9a-f]{2})([0-9a-f]{2})\\.([0-9a-f]{2})([0-9a-f]{2})\\.([0-9a-f]{2})([0-9a-f]{2}))", icase: TRUE )){
		if( !isnull( mac[8] ) ) {
			final_mac = mac[8] + ":" + mac[9] + ":" + mac[10] + ":" + mac[11] + ":" + mac[12] + ":" + mac[13];
		}
		else {
			final_mac = mac[2] + ":" + mac[3] + ":" + mac[4] + ":" + mac[5] + ":" + mac[6] + ":" + mac[7];
		}
		final_mac = tolower( final_mac );
		register_host_detail( name: "MAC", value: final_mac, desc: desc );
		replace_kb_item( name: "Host/mac_address", value: final_mac );
		return final_mac;
	}
	return FALSE;
}
func tcp_extract_option_field( ip, option, debug ){
	var ip, option, debug;
	var hl, hlen, tcp, flags, opt, lo, i, n, tsval, tsecr, scount, len;
	if(isnull( ip )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#ip#-#tcp_extract_option_field" );
		return NULL;
	}
	if(!option){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#option#-#tcp_extract_option_field" );
		return NULL;
	}
	if(strlen( ip ) < 20){
		return NULL;
	}
	if(!ContainsString( tolower( option ), "timestamp" ) && !ContainsString( tolower( option ), "wscale" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#tcp_extract_option_field: Invalid option passed to 'option' parameter: " + option + ". Currently supported: 'Timestamp' and 'WScale'" );
		return NULL;
	}
	hl = ord( ip[0] );
	hlen = ( hl & 0xF ) * 4;
	tcp = substr( ip, hlen );
	if(debug){
		dump( ddata: ip, dtitle: "IP" );
		dump( ddata: tcp, dtitle: "TCP" );
	}
	if(strlen( tcp ) <= 20){
		return NULL;
	}
	flags = ord( tcp[13] );
	if(!( flags & TH_ACK )){
		return NULL;
	}
	opt = substr( tcp, 20 );
	if(debug){
		dump( ddata: opt, dtitle: "TCP options" );
	}
	lo = strlen( opt );
	for(i = 0;i < lo;){
		n = ord( opt[i] );
		if( ContainsString( tolower( option ), "timestamp" ) && n == 8 ){
			tsval = ntohl( n: substr( opt, i + 2, i + 5 ) );
			if(int( tsval ) == NULL){
				return NULL;
			}
			tsecr = ntohl( n: substr( opt, i + 6, i + 9 ) );
			if(debug){
				display( "TSVal=", tsval, " TSecr=", tsecr );
			}
			return tsval;
		}
		else {
			if( ContainsString( tolower( option ), "wscale" ) && n == 3 ){
				scount = ord( opt[i + 2] );
				if(!isnull( scount )){
					if(debug){
						display( "---[ Extracted WScale Shift count ]---\n\n", scount );
					}
					return scount;
				}
			}
			else {
				if( n == 1 ){
					i++;
				}
				else {
					len = ord( opt[i + 1] );
					if(len == 0){
						break;
					}
					i += len;
				}
			}
		}
	}
	return NULL;
}

