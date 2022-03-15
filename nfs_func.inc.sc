func padsz( len ){
	if( len % 4 ) {
		return 4 - len % 4;
	}
	else {
		return 0;
	}
}
func rpclong( val ){
	var ret;
	ret = raw_string( val / ( 256 * 256 * 256 ), val / ( 256 * 256 ), val / 256, val % 256 );
	return ret;
}
func str2long( val, idx ){
	var ret;
	ret = ord( val[idx] ) * 256 * 256 * 256 + ord( val[idx + 1] ) * 256 * 256 + ord( val[idx + 2] ) * 256 + ord( val[idx + 3] );
	return int( ret );
}
func rpcpad( pad ){
	return crap( length: pad, data: raw_string( 0 ) );
}
func mount( soc, share ){
	var pad, req, len, r, ret, i;
	pad = padsz( len: strlen( this_host_name() ) );
	len = 52 + strlen( this_host_name() ) + pad;
	req = rpclong( val: rand() ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 100005 ) + rpclong( val: 1 ) + rpclong( val: 1 ) + rpclong( val: 1 ) + rpclong( val: len ) + rpclong( val: rand() ) + rpclong( val: strlen( this_host_name() ) ) + this_host_name() + rpcpad( pad: pad ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 7 ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 3 ) + rpclong( val: 4 ) + rpclong( val: 5 ) + rpclong( val: 20 ) + rpclong( val: 31 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: strlen( share ) ) + share + rpcpad( pad: padsz( len: strlen( share ) ) );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: 4096 );
	if( strlen( r ) < 24 ) {
		return NULL;
	}
	else {
		if(str2long( val: r, idx: 24 ) != 0){
			return NULL;
		}
		ret = "";
		for(i = 28;i < 60;i++){
			ret += r[i];
		}
		return ret;
	}
}
func readdir( soc, fid ){
	var req, r, i, dir, ret;
	req = rpclong( val: rand() ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 100003 ) + rpclong( val: 2 ) + rpclong( val: 16 ) + rpclong( val: 1 ) + rpclong( val: 48 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 7 ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 3 ) + rpclong( val: 4 ) + rpclong( val: 5 ) + rpclong( val: 20 ) + rpclong( val: 31 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + fid + rpclong( val: 0 ) + rpclong( val: 8192 );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: 8192 );
	if(strlen( r ) <= 24){
		return NULL;
	}
	if(str2long( val: r, idx: 24 ) != 0){
		return NULL;
	}
	i = 28;
	ret = make_list();
	for(;str2long( val: r, idx: i ) == 1;){
		if(i > strlen( r )){
			break;
		}
		i += 4;
		i += 4;
		len = str2long( val: r, idx: i );
		i += 4;
		dir = substr( r, i, i + len - 1 );
		i += len;
		i += padsz( len: len );
		i += 4;
		ret = make_list( ret,
			 dir );
	}
	return ret;
}
func cwd( soc, dir, fid ){
	var req, ret, i;
	req = rpclong( val: rand() ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 100003 ) + rpclong( val: 2 ) + rpclong( val: 4 ) + rpclong( val: 1 ) + rpclong( val: 48 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 7 ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 3 ) + rpclong( val: 4 ) + rpclong( val: 5 ) + rpclong( val: 20 ) + rpclong( val: 31 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + fid + rpclong( val: strlen( dir ) ) + dir + rpcpad( pad: padsz( len: strlen( dir ) ) );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: 8192 );
	if(strlen( r ) < 24){
		return NULL;
	}
	if( strlen( r ) < 24 ) {
		return NULL;
	}
	else {
		if(str2long( val: r, idx: 24 ) != 0){
			return NULL;
		}
		ret = "";
		for(i = 28;i < 56;i++){
			ret += r[i];
		}
		ret += rpclong( val: 0 );
		return ret;
	}
}
func open( soc, file, fid ){
	var req, ret, i;
	req = rpclong( val: rand() ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 100003 ) + rpclong( val: 2 ) + rpclong( val: 4 ) + rpclong( val: 1 ) + rpclong( val: 48 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 7 ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 3 ) + rpclong( val: 3 ) + rpclong( val: 5 ) + rpclong( val: 20 ) + rpclong( val: 31 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + fid + rpclong( val: strlen( file ) ) + file + rpcpad( pad: padsz( len: strlen( file ) ) );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: 8192 );
	if(strlen( r ) < 24){
		return NULL;
	}
	if( strlen( r ) < 24 ) {
		return NULL;
	}
	else {
		if(str2long( val: r, idx: 24 ) != 0){
			return NULL;
		}
		ret = "";
		for(i = 28;i < 56;i++){
			ret += r[i];
		}
		ret += rpclong( val: 0 );
		return ret;
	}
}
func read( soc, fid, length, off ){
	var req, ret, i, len;
	req = rpclong( val: rand() ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 100003 ) + rpclong( val: 2 ) + rpclong( val: 6 ) + rpclong( val: 1 ) + rpclong( val: 48 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 7 ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 3 ) + rpclong( val: 4 ) + rpclong( val: 5 ) + rpclong( val: 20 ) + rpclong( val: 31 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + fid + rpclong( val: off ) + rpclong( val: length ) + rpclong( val: 0 );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: length + 33 );
	if(strlen( r ) <= 32){
		return NULL;
	}
	return substr( r, 32, strlen( r ) - 1 );
}
func umount( soc, share ){
	var pad, req, len, r, ret, i;
	pad = padsz( len: strlen( this_host_name() ) );
	len = 52 + strlen( this_host_name() ) + pad;
	req = rpclong( val: rand() ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 100005 ) + rpclong( val: 1 ) + rpclong( val: 3 ) + rpclong( val: 1 ) + rpclong( val: len ) + rpclong( val: rand() ) + rpclong( val: strlen( this_host_name() ) ) + this_host_name() + rpcpad( pad: pad ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 7 ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 3 ) + rpclong( val: 4 ) + rpclong( val: 5 ) + rpclong( val: 20 ) + rpclong( val: 31 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: strlen( share ) ) + share + rpcpad( pad: padsz( len: strlen( share ) ) );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: 8192 );
}

