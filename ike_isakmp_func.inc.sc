var ENCRYPTION_ALGORITHMS, AUTHENTICATION_METHODS, HASH_ALGORITHMS, GROUP_DESCRIPTIONS, EXCHANGE_TYPES_RAW, PROTOCOL_IDS;
var EXCHANGE_TYPES, PAYLOADS, PAYLOADS_RAW, VERSIONS, VERSIONS_RAW, ID_TYPES, ID_TYPES_RAW;
ENCRYPTION_ALGORITHMS["des"] = raw_string( 0x80, 0x01, 0x00, 0x01 );
ENCRYPTION_ALGORITHMS["3des"] = raw_string( 0x80, 0x01, 0x00, 0x05 );
ENCRYPTION_ALGORITHMS["cast"] = raw_string( 0x80, 0x01, 0x00, 0x06 );
ENCRYPTION_ALGORITHMS["aes/128"] = make_list( raw_string( 0x80,
	 0x01,
	 0x00,
	 0x07 ),
	 raw_string( 0x80,
	 0x0E,
	 0x00,
	 0x80 ) );
ENCRYPTION_ALGORITHMS["aes/192"] = make_list( raw_string( 0x80,
	 0x01,
	 0x00,
	 0x07 ),
	 raw_string( 0x80,
	 0x0E,
	 0x00,
	 0xC0 ) );
ENCRYPTION_ALGORITHMS["aes/256"] = make_list( raw_string( 0x80,
	 0x01,
	 0x00,
	 0x07 ),
	 raw_string( 0x80,
	 0x0E,
	 0x01,
	 0x00 ) );
AUTHENTICATION_METHODS["psk"] = raw_string( 0x80, 0x03, 0x00, 0x01 );
AUTHENTICATION_METHODS["rsa"] = raw_string( 0x80, 0x03, 0x00, 0x03 );
AUTHENTICATION_METHODS["ECDSA"] = raw_string( 0x80, 0x03, 0x00, 0x08 );
AUTHENTICATION_METHODS["Hybrid"] = raw_string( 0x80, 0x03, 0xFA, 0xDD );
AUTHENTICATION_METHODS["XAUTH"] = raw_string( 0x80, 0x03, 0xFD, 0xE9 );
HASH_ALGORITHMS["md5"] = raw_string( 0x80, 0x02, 0x00, 0x01 );
HASH_ALGORITHMS["sha1"] = raw_string( 0x80, 0x02, 0x00, 0x02 );
HASH_ALGORITHMS["sha2-256"] = raw_string( 0x80, 0x02, 0x00, 0x04 );
HASH_ALGORITHMS["sha2-384"] = raw_string( 0x80, 0x02, 0x00, 0x05 );
HASH_ALGORITHMS["sha2-512"] = raw_string( 0x80, 0x02, 0x00, 0x06 );
GROUP_DESCRIPTIONS["768"] = raw_string( 0x80, 0x04, 0x00, 0x01 );
GROUP_DESCRIPTIONS["1024"] = raw_string( 0x80, 0x04, 0x00, 0x02 );
GROUP_DESCRIPTIONS["1536"] = raw_string( 0x80, 0x04, 0x00, 0x05 );
GROUP_DESCRIPTIONS["2048"] = raw_string( 0x80, 0x04, 0x00, 0x0E );
GROUP_DESCRIPTIONS["3072"] = raw_string( 0x80, 0x04, 0x00, 0x0F );
GROUP_DESCRIPTIONS["4096"] = raw_string( 0x80, 0x04, 0x00, 0x10 );
GROUP_DESCRIPTIONS["6144"] = raw_string( 0x80, 0x04, 0x00, 0x11 );
GROUP_DESCRIPTIONS["8192"] = raw_string( 0x80, 0x04, 0x00, 0x12 );
EXCHANGE_TYPES[raw_string( 0x02 )] = "Identity Protection (Main Mode)";
EXCHANGE_TYPES[raw_string( 0x04 )] = "Aggressive";
EXCHANGE_TYPES[raw_string( 0x05 )] = "Informational";
EXCHANGE_TYPES_RAW["Identity Protection (Main Mode)"] = raw_string( 0x02 );
EXCHANGE_TYPES_RAW["Aggressive"] = raw_string( 0x04 );
EXCHANGE_TYPES_RAW["Informational"] = raw_string( 0x05 );
PROTOCOL_IDS["tcp"] = raw_string( 0x06 );
PROTOCOL_IDS["udp"] = raw_string( 0x11 );
PAYLOADS[raw_string( 0x00 )] = "NONE";
PAYLOADS[raw_string( 0x01 )] = "Security Association";
PAYLOADS[raw_string( 0x02 )] = "Proposal";
PAYLOADS[raw_string( 0x03 )] = "Transform";
PAYLOADS[raw_string( 0x04 )] = "Key Exchange";
PAYLOADS[raw_string( 0x05 )] = "Identification";
PAYLOADS[raw_string( 0x08 )] = "Hash";
PAYLOADS[raw_string( 0x0A )] = "Nonce";
PAYLOADS[raw_string( 0x0B )] = "Notification";
PAYLOADS[raw_string( 0x0D )] = "Vendor ID";
PAYLOADS_RAW["NONE"] = raw_string( 0x00 );
PAYLOADS_RAW["Security Association"] = raw_string( 0x01 );
PAYLOADS_RAW["Proposal"] = raw_string( 0x02 );
PAYLOADS_RAW["Transform"] = raw_string( 0x03 );
PAYLOADS_RAW["Key Exchange"] = raw_string( 0x04 );
PAYLOADS_RAW["Identification"] = raw_string( 0x05 );
PAYLOADS_RAW["Hash"] = raw_string( 0x08 );
PAYLOADS_RAW["Nonce"] = raw_string( 0x0A );
PAYLOADS_RAW["Notification"] = raw_string( 0x0B );
PAYLOADS_RAW["Vendor ID"] = raw_string( 0x0D );
VERSIONS[raw_string( 0x10 )] = "1.0";
VERSIONS[raw_string( 0x20 )] = "2.0";
VERSIONS_RAW["1.0"] = raw_string( 0x10 );
VERSIONS_RAW["2.0"] = raw_string( 0x20 );
ID_TYPES[raw_string( 0x01 )] = "IPV4_ADDR";
ID_TYPES[raw_string( 0x03 )] = "USER_FQDN";
ID_TYPES[raw_string( 0x05 )] = "IPV6_ADDR";
ID_TYPES_RAW["IPV4_ADDR"] = raw_string( 0x01 );
ID_TYPES_RAW["USER_FQDN"] = raw_string( 0x03 );
ID_TYPES_RAW["IPV6_ADDR"] = raw_string( 0x05 );
func isakmp_open_socket( port, proto ){
	var port, proto;
	var sport, soc;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#isakmp_open_socket" );
		return NULL;
	}
	if(!proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#isakmp_open_socket" );
		proto = "udp";
	}
	if( port == 4500 ) {
		sport = port;
	}
	else {
		sport = 500;
	}
	if( proto == "tcp" ){
		if(!get_tcp_port_state( port )){
			return FALSE;
		}
		if( islocalhost() ) {
			soc = open_sock_tcp( port );
		}
		else {
			soc = open_priv_sock_tcp( sport: sport, dport: port );
		}
		if(!soc){
			return FALSE;
		}
	}
	else {
		if(!get_udp_port_state( port )){
			return FALSE;
		}
		if( islocalhost() ) {
			soc = open_sock_udp( port );
		}
		else {
			soc = open_priv_sock_udp( sport: sport, dport: port );
		}
		if(!soc){
			return FALSE;
		}
	}
	return soc;
}
func isakmp_send_recv( soc, port, data, initiator_spi, use_pcap, proto, debug ){
	var soc, port, data, initiator_spi, use_pcap, proto, debug;
	var srcport, ownip, targetip, dstport, initiator_spi_hex, pcap_filter;
	var res, res_initiator_spi, ike_vers;
	if(!soc && !port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#soc and port#-#isakmp_send_recv" );
		return NULL;
	}
	if(use_pcap && !port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#isakmp_send_recv" );
		return NULL;
	}
	if(!use_pcap && !soc){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#soc#-#isakmp_send_recv" );
		return NULL;
	}
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#isakmp_send_recv" );
		return NULL;
	}
	if(!initiator_spi){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#initiator_spi#-#isakmp_send_recv" );
		return NULL;
	}
	if(!proto){
		proto = "udp";
	}
	if( use_pcap ){
		if( islocalhost() ) {
			srcport = rand() % ( 65536 - 1024 ) + 1024;
		}
		else {
			if( port == 4500 ) {
				srcport = port;
			}
			else {
				srcport = 500;
			}
		}
		ownip = this_host();
		targetip = get_host_ip();
		dstport = port;
		initiator_spi_hex = "0x" + hexstr( substr( initiator_spi, 0, 3 ) );
		if( proto == "tcp" ){
			if( TARGET_IS_IPV6() ){
				pcap_filter = "src host " + targetip + " and dst host " + ownip + " and tcp and tcp src port " + dstport + " and tcp dst port " + srcport;
			}
			else {
				pcap_filter = "src host " + targetip + " and dst host " + ownip + " and tcp and tcp src port " + dstport + " and tcp dst port " + srcport + " and tcp[20:4] = " + initiator_spi_hex;
			}
		}
		else {
			if( TARGET_IS_IPV6() ){
				pcap_filter = "src host " + targetip + " and dst host " + ownip + " and udp and udp src port " + dstport + " and udp dst port " + srcport;
			}
			else {
				pcap_filter = "src host " + targetip + " and dst host " + ownip + " and udp and udp src port " + dstport + " and udp dst port " + srcport + " and udp[8:4] = " + initiator_spi_hex;
			}
		}
		res = pcap_tcp_udp_send_recv( port: port, srcport: srcport, data: data, proto: proto, debug: debug, pcap_filter: pcap_filter );
	}
	else {
		send( socket: soc, data: data );
		res = recv( socket: soc, length: 4096 );
	}
	if(!res || strlen( res ) < 28){
		if(debug){
			display( "---[ Too short (expected length: 28) " + toupper( proto ) + " data packet received ]---" );
		}
		return NULL;
	}
	if(!res_initiator_spi = substr( res, 0, 7 )){
		if(debug){
			display( "---[ Failed to extract Initiator SPI from packet ]---" );
		}
		return NULL;
	}
	if(res_initiator_spi != initiator_spi){
		if(debug){
			display( "---[ Sent Initiator SPI '", initiator_spi, "' doesn't match received Initiator SPI'", res_initiator_spi, "' ]---" );
		}
		return NULL;
	}
	if(!ike_vers = res[17]){
		if(debug){
			display( "---[ Failed to extract IKE/ISAKMP version from received " + toupper( proto ) + " data packet ]---" );
		}
		return NULL;
	}
	if(!VERSIONS[ike_vers]){
		if(debug){
			display( "---[ Unsupported IKE/ISAKMP version received: '0x", hexstr( ike_vers ), "'. Currently supported: 0x10 (1.0) and 0x20 (2.0) ]---" );
		}
		return NULL;
	}
	return res;
}
func isakmp_create_transforms_packet_from_list( enable_short_list ){
	var enable_short_list;
	var supported_auth_method_list, supported_encryption_algo_list, supported_hash_algo_list, supported_group_desc_list;
	var max_transforms, current_transform, packet, supported_auth, supported_encryption, supported_hash, supported_group;
	if( enable_short_list ){
		supported_auth_method_list = make_list( "psk" );
		supported_encryption_algo_list = make_list( "des",
			 "3des" );
		supported_hash_algo_list = make_list( "md5",
			 "sha1" );
		supported_group_desc_list = make_list( "768",
			 "1024" );
	}
	else {
		supported_auth_method_list = make_list( "psk",
			 "rsa",
			 "Hybrid",
			 "XAUTH" );
		supported_encryption_algo_list = make_list( "des",
			 "3des",
			 "aes/128",
			 "aes/192",
			 "aes/256" );
		supported_hash_algo_list = make_list( "md5",
			 "sha1" );
		supported_group_desc_list = make_list( "768",
			 "1024",
			 "1536",
			 "2048",
			 "3072",
			 "4096",
			 "6144",
			 "8192" );
	}
	max_transforms = max_index( supported_auth_method_list ) * max_index( supported_encryption_algo_list ) * max_index( supported_hash_algo_list ) * max_index( supported_group_desc_list );
	current_transform = 0;
	for supported_auth_method in supported_auth_method_list {
		for supported_encryption_algo in supported_encryption_algo_list {
			for supported_hash_algo in supported_hash_algo_list {
				for supported_group_desc in supported_group_desc_list {
					current_transform++;
					packet += isakmp_create_transforms_packet_single( encryption_algo: supported_encryption_algo, auth_method: supported_auth_method, hash_algo: supported_hash_algo, group_desc: supported_group_desc, max_transforms: max_transforms, current_transform: current_transform );
				}
			}
		}
	}
	return make_list( packet,
		 max_transforms );
}
func isakmp_create_transforms_packet_single( encryption_algo, auth_method, hash_algo, group_desc, max_transforms, current_transform ){
	var encryption_algo, auth_method, hash_algo, group_desc, max_transforms, current_transform;
	var trans_length, encryption_algo_info, enc, key_length, next_payload, packet;
	if(!encryption_algo){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_transforms_packet_single#-#encryption_algo" );
		return NULL;
	}
	if(!auth_method){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_transforms_packet_single#-#auth_method" );
		return NULL;
	}
	if(!hash_algo){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_transforms_packet_single#-#hash_algo" );
		return NULL;
	}
	if(!group_desc){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_transforms_packet_single#-#group_desc" );
		return NULL;
	}
	if(!IsMatchRegexp( encryption_algo, "^(des|3des|aes/128|aes/192|aes/256)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_transforms_packet_single(): Unsupported Encryption-Algorithm '" + encryption_algo + "' given to 'encryption_algo' parameter. Currently supported: des, 3des, aes/128, aes/192, aes/256" );
		return NULL;
	}
	if(!IsMatchRegexp( auth_method, "^(psk|rsa|Hybrid|XAUTH)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_transforms_packet_single(): Unsupported Authentication-Method '" + auth_method + "' given to 'auth_method' parameter. Currently supported: psk, rsa, Hybrid, XAUTH" );
		return NULL;
	}
	if(!IsMatchRegexp( hash_algo, "^(md5|sha1)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_transforms_packet_single(): Unsupported Hash-Algorithm '" + hash_algo + "' given to 'hash_algo' parameter. Currently supported: md5, sha1" );
		return NULL;
	}
	if(!IsMatchRegexp( group_desc, "^(768|1024|1536|2048|3072|4096|6144|8192)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_transforms_packet_single(): Unsupported Group-Description '" + group_desc + "' given to 'group_desc' parameter. Currently supported: 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192" );
		return NULL;
	}
	if( IsMatchRegexp( encryption_algo, "^aes/" ) ){
		trans_length = raw_string( 0x00, 0x28 );
		encryption_algo_info = ENCRYPTION_ALGORITHMS[encryption_algo];
		encryption_algo_raw = encryption_algo_info[0];
		key_length = encryption_algo_info[1];
	}
	else {
		trans_length = raw_string( 0x00, 0x24 );
		encryption_algo_raw = ENCRYPTION_ALGORITHMS[encryption_algo];
		key_length = "";
	}
	if( current_transform == max_transforms ) {
		next_payload = PAYLOADS_RAW["NONE"];
	}
	else {
		next_payload = PAYLOADS_RAW["Transform"];
	}
	packet = next_payload;
	packet += raw_string( 0x00 );
	packet += trans_length;
	packet += mkbyte( current_transform );
	packet += raw_string( 0x01 );
	packet += raw_string( 0x00, 0x00 );
	packet += encryption_algo_raw;
	packet += HASH_ALGORITHMS[hash_algo];
	packet += AUTHENTICATION_METHODS[auth_method];
	packet += GROUP_DESCRIPTIONS[group_desc];
	if(key_length){
		packet += key_length;
	}
	packet += raw_string( 0x80, 0x0b, 0x00, 0x01 );
	packet += raw_string( 0x00, 0x0c, 0x00, 0x04, 0x00, 0x00, 0x70, 0x80 );
	return packet;
}
func isakmp_generate_aggressive_packet( port, ipproto, dhgroup, aggressive_mode_id ){
	var port, ipproto, dhgroup, aggressive_mode_id;
	var id_type, ip_dot, int32, octet, key_length, packet;
	if(ipproto && !IsMatchRegexp( ipproto, "^(tcp|udp)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_generate_aggressive_packet(): Unsupported protocol '" + ipproto + "' given to 'ipproto' parameter. Currently supported: udp, tcp" );
		return NULL;
	}
	if(dhgroup && !IsMatchRegexp( dhgroup, "^(1|2|5|14|15|16|17|18)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_generate_aggressive_packet(): Unsupported Diffie Hellman Group '" + dhgroup + "' given to 'dhgroup' parameter. Currently supported:1,2,5,14,15,16,17,18 (MODP only)" );
		return NULL;
	}
	if(!port){
		port = 500;
	}
	if(!ipproto){
		ipproto = "udp";
	}
	if(!dhgroup){
		dhgroup = 2;
	}
	if( isnull( aggressive_mode_id ) ){
		aggressive_mode_id = "vpngroup";
		id_type = "USER_FQDN";
	}
	else {
		if( TARGET_IS_IPV6() && ContainsString( aggressive_mode_id, ":" ) ){
			id_type = "IPV6_ADDR";
		}
		else {
			if( !TARGET_IS_IPV6() && IsMatchRegexp( aggressive_mode_id, "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" ) ){
				id_type = "IPV4_ADDR";
				ip_dot = split( buffer: aggressive_mode_id, sep: ".", keep: FALSE );
				int32 = "";
				for(octet = 0;octet < 4;octet++){
					int32 = raw_string( int32, int( ip_dot[octet] ) );
				}
				aggressive_mode_id = int32;
			}
			else {
				id_type = "USER_FQDN";
			}
		}
	}
	if( dhgroup == 1 ) {
		key_length = 96;
	}
	else {
		if( dhgroup == 2 ) {
			key_length = 128;
		}
		else {
			if( dhgroup == 5 ) {
				key_length = 192;
			}
			else {
				if( dhgroup == 14 ) {
					key_length = 256;
				}
				else {
					if( dhgroup == 15 ) {
						key_length = 384;
					}
					else {
						if( dhgroup == 16 ) {
							key_length = 512;
						}
						else {
							if( dhgroup == 17 ) {
								key_length = 768;
							}
							else {
								if(dhgroup == 18){
									key_length = 1024;
								}
							}
						}
					}
				}
			}
		}
	}
	packet = PAYLOADS_RAW["Nonce"];
	packet += raw_string( 0x00 );
	packet += mkword( key_length + 4 );
	packet += raw_string( rand_str( length: key_length, charset: "abcdefghiklmnopqrstuvwxyz0123456789" ) );
	packet += PAYLOADS_RAW["Identification"];
	packet += raw_string( 0x00 );
	packet += mkword( 20 + 4 );
	packet += raw_string( rand_str( length: 20, charset: "abcdefghiklmnopqrstuvwxyz0123456789" ) );
	packet += PAYLOADS_RAW["NONE"];
	packet += raw_string( 0x00 );
	packet += mkword( strlen( aggressive_mode_id ) + 4 + 4 );
	packet += ID_TYPES_RAW[id_type];
	packet += PROTOCOL_IDS[ipproto];
	packet += mkword( port );
	packet += aggressive_mode_id;
	return packet;
}
func isakmp_create_request_packet( port, ipproto, exchange_type, transforms, transforms_num, dhgroup, aggressive_mode_id, initiator_spi ){
	var port, ipproto, exchange_type, transforms, transforms_num, dhgroup, aggressive_mode_id, initiator_spi;
	var agressive_packet, sa_next_payload, main_packet;
	if(!transforms){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_request_packet#-#transforms" );
		return NULL;
	}
	if(isnull( transforms_num )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_request_packet#-#transforms_num" );
		return NULL;
	}
	if(ipproto && !IsMatchRegexp( ipproto, "^(tcp|udp)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_request_packet(): Unsupported protocol '" + ipproto + "' given to 'ipproto' parameter. Currently supported: udp, tcp" );
		return NULL;
	}
	if(exchange_type && !IsMatchRegexp( exchange_type, "^(Identity Protection \\(Main Mode\\)|Aggressive)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_request_packet(): Unsupported exchange type '" + exchange_type + "' given to 'exchange_type' parameter. Currently supported: Identity Protection (Main Mode), Aggressive" );
		return NULL;
	}
	if(dhgroup && !IsMatchRegexp( dhgroup, "^(1|2|5|14|15|16|17|18)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#isakmp_create_request_packet(): Unsupported Diffie Hellman Group '" + dhgroup + "' given to 'dhgroup' parameter. Currently supported:1,2,5,14,15,16,17,18 (MODP only)" );
		return NULL;
	}
	if(!port){
		port = 500;
	}
	if(!ipproto){
		ipproto = "udp";
	}
	if(!exchange_type){
		exchange_type = "Identity Protection (Main Mode)";
	}
	if(!dhgroup){
		dhgroup = 2;
	}
	if( exchange_type == "Aggressive" ){
		if(isnull( aggressive_mode_id )){
			aggressive_mode_id = "vpngroup";
		}
		aggressive_packet = isakmp_generate_aggressive_packet( port: port, ipproto: ipproto, dhgroup: dhgroup, aggressive_mode_id: aggressive_mode_id );
		sa_next_payload = PAYLOADS_RAW["Key Exchange"];
	}
	else {
		aggressive_packet = "";
		sa_next_payload = PAYLOADS_RAW["NONE"];
	}
	if(!initiator_spi){
		initiator_spi = rand_str( length: 8, charset: "abcdefghiklmnopqrstuvwxyz0123456789" );
	}
	main_packet = raw_string( initiator_spi );
	main_packet += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
	main_packet += PAYLOADS_RAW["Security Association"];
	main_packet += VERSIONS_RAW["1.0"];
	main_packet += EXCHANGE_TYPES_RAW[exchange_type];
	main_packet += raw_string( 0x00 );
	main_packet += raw_string( 0x00, 0x00, 0x00, 0x00 );
	main_packet += mkdword( 48 + strlen( transforms ) + strlen( aggressive_packet ) );
	main_packet += sa_next_payload;
	main_packet += raw_string( 0x00 );
	main_packet += mkword( 20 + strlen( transforms ) );
	main_packet += raw_string( 0x00, 0x00, 0x00, 0x01 );
	main_packet += raw_string( 0x00, 0x00, 0x00, 0x01 );
	main_packet += PAYLOADS_RAW["NONE"];
	main_packet += raw_string( 0x00 );
	main_packet += mkword( 8 + strlen( transforms ) );
	main_packet += raw_string( 0x01 );
	main_packet += raw_string( 0x01 );
	main_packet += raw_string( 0x00 );
	main_packet += mkbyte( transforms_num );
	main_packet += transforms;
	if(exchange_type == "Aggressive"){
		main_packet += aggressive_packet;
	}
	return main_packet;
}

