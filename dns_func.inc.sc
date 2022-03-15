func dnsVersionReq( soc, proto, port ){
	var soc, proto, port;
	var raw_data_init, queries, query_list, _query, _query_str, len, raw_data, offset, result, base, size, slen, whole_data, i;
	if(!soc){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#soc#-#dnsVersionReq" );
		return NULL;
	}
	if(!proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#dnsVersionReq" );
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#dnsVersionReq" );
	}
	raw_data_init = raw_string( 0x00, 0x0A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07 );
	queries = make_list( "version",
		 "version.pdns",
		 "version.bind",
		 "version.server",
		 "erre-con-erre-cigarro.maradns.org",
		 "version.maradns",
		 "version.mydns" );
	query_list = make_list();
	for _query in queries {
		query_list = make_list( query_list,
			 _query,
			 toupper( _query ) );
	}
	for _query_str in query_list {
		if( proto == "tcp" ){
			len = strlen( _query_str ) + 18;
			raw_data = raw_string( 0x00, len ) + raw_data_init;
			offset = 2;
		}
		else {
			offset = 0;
			raw_data = raw_data_init;
		}
		_query_str = str_replace( string: _query_str, find: ".", replace: raw_string( 0x04 ) );
		raw_data = raw_data + _query_str;
		raw_data = raw_data + raw_string( 0x00, 0x00, 0x10, 0x00, 0x03 );
		send( socket: soc, data: raw_data );
		result = recv( socket: soc, length: 1000 );
		if(result){
			if(( ( result[0 + offset] == raw_string( 0x00 ) ) || ( result[0 + offset] == raw_string( 0xA5 ) ) ) && ( ( result[1 + offset] == raw_string( 0x0A ) ) || ( result[1 + offset] == raw_string( 0x12 ) ) )){
				if(( ( result[2 + offset] == raw_string( 0x81 ) ) || ( result[2 + offset] == raw_string( 0x84 ) ) || ( result[2 + offset] == raw_string( 0x85 ) ) ) && ( ( result[3 + offset] == raw_string( 0x80 ) ) || ( result[3 + offset] == raw_string( 0x00 ) ) )){
					if(( result[4 + offset] == raw_string( 0x00 ) ) && ( result[5 + offset] == raw_string( 0x01 ) )){
						if(( result[6 + offset] == raw_string( 0x00 ) ) && ( result[7 + offset] == raw_string( 0x01 ) )){
							if( result[18 + strlen( _query_str ) + offset] >= 0xc0 ){
								base = 28 + strlen( _query_str );
							}
							else {
								base = 40 + strlen( _query_str );
							}
							size = ord( result[base + 1 + offset] );
							slen = base + 3 + offset - 1;
							if(slen > strlen( result )){
								return;
							}
							if(size > 0){
								whole_data = "";
								for(i = 0;i < size - 1;i++){
									whole_data = whole_data + result[base + 3 + i + offset];
								}
								set_kb_item( name: "DNS/" + proto + "/version_request", value: port );
								set_kb_item( name: "DNS/" + proto + "/version_request/" + port, value: whole_data );
								return whole_data;
							}
						}
					}
				}
			}
		}
	}
}

