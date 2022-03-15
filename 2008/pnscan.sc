if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80001" );
	script_version( "2021-03-23T06:51:29+0000" );
	script_tag( name: "last_modification", value: "2021-03-23 06:51:29 +0000 (Tue, 23 Mar 2021)" );
	script_tag( name: "creation_date", value: "2008-08-31 23:34:05 +0200 (Sun, 31 Aug 2008)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "pnscan (NASL wrapper)" );
	script_category( ACT_SCANNER );
	script_copyright( "Copyright (C) 2008 Vlatko Kosturjak" );
	script_family( "Port scanners" );
	script_dependencies( "toolcheck.sc", "host_alive_detection.sc" );
	script_mandatory_keys( "Tools/Present/pnscan" );
	script_add_preference( name: "Pnscan Timeout", type: "entry", value: "", id: 1 );
	script_add_preference( name: "Pnscan Concurrent worker threads", type: "entry", value: "", id: 2 );
	script_tag( name: "summary", value: "This plugin runs pnscan to find open ports.
  Pnscan is a lite multi-threaded port scanner." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
ip = get_host_ip();
esc_ip = "";
l = strlen( ip );
for(i = 0;i < l;i++){
	if( ip[i] == "." ) {
		esc_ip = strcat( esc_ip, "\\." );
	}
	else {
		esc_ip = strcat( esc_ip, ip[i] );
	}
}
prange = get_preference( "port_range" );
if(!prange){
	prange = "1-65535";
}
portrangelist = split( buffer: prange, sep: ",", keep: FALSE );
size = max_index( portrangelist );
i = 0;
j = 0;
new_portrangelist = make_array();
tcp = 1;
for(i = 0;i < size;i++){
	if( substr( portrangelist[i], 0, 1 ) == "U:" ){
		tcp = 0;
	}
	else {
		if( substr( portrangelist[i], 0, 1 ) == "T:" ){
			new_portrangelist[j] = substr( portrangelist[i], 2 );
			j++;
			tcp = 1;
		}
		else {
			if(tcp == 1){
				new_portrangelist[j] = portrangelist[i];
				j++;
			}
		}
	}
}
portrangelist = new_portrangelist;
i = 0;
j = 0;
l = 0;
for(i = 0;i < size;i++){
	beg = split( buffer: portrangelist[i], sep: "-", keep: FALSE );
	if( isnull( beg[1] ) ){
		portrangelist[i] = beg[0];
	}
	else {
		if(int( beg[0] ) > int( beg[1] )){
			tmpvar = beg[0];
			beg[0] = beg[1];
			beg[1] = tmpvar;
		}
		portrangelist[i] = beg[0] + "-" + beg[1];
	}
	for(j = i;j < size;j++){
		prs = split( buffer: portrangelist[j], sep: "-", keep: FALSE );
		prsnext = split( buffer: portrangelist[j + 1], sep: "-", keep: FALSE );
		if(isnull( prs[1] ) && isnull( prsnext[1] )){
			if( prsnext[0] == ( int( prs[0] ) + 1 ) ){
				beg[1] = prsnext[0];
				i++;
			}
			else {
				break;
			}
		}
		if(isnull( prs[1] ) && ( !isnull( prsnext[1] ) )){
			if( prsnext[0] == int( prs[0] + 1 ) ){
				beg[1] = prsnext[1];
				i++;
			}
			else {
				break;
			}
		}
		if(( !isnull( prs[1] ) ) && isnull( prsnext[1] )){
			if( prsnext[0] == int( prs[1] + 1 ) ){
				beg[1] = prsnext[0];
				i++;
			}
			else {
				break;
			}
		}
		if(( !isnull( prs[1] ) ) && ( !isnull( prsnext[1] ) )){
			if( prsnext[0] == int( prs[1] + 1 ) ){
				beg[1] = prsnext[1];
				i++;
			}
			else {
				break;
			}
		}
	}
	if( isnull( beg[1] ) ){
		prlist[l] = beg[0];
	}
	else {
		prlist[l] = beg[0] + "-" + beg[1];
	}
	l++;
}
n_ports = 0;
oports[0] = 0;
for pr in prlist {
	i = 0;
	argv[i++] = "pnscan";
	argv[i++] = "-l";
	p = script_get_preference( name: "Pnscan Timeout", id: 1 );
	if(p){
		argv[i++] = "-t " + p;
	}
	p = script_get_preference( name: "Pnscan Concurrent worker threads", id: 2 );
	if(p){
		argv[i++] = "-n " + p;
	}
	argv[i++] = ip;
	pr2 = ereg_replace( string: pr, pattern: "-", replace: ":", icase: FALSE );
	argv[i++] = pr2;
	res = pread( cmd: "pnscan", argv: argv, cd: 1, nice: 5 );
	for line in split( res ) {
		v = eregmatch( string: line, pattern: "^" + esc_ip + " *: *([0-9]+) *:([^:]*): *(.*)$" );
		if(!isnull( v )){
			port = v[1];
			if(isnull( oports[port] )){
				n_ports++;
				oports[port] = port;
				proto = "tcp";
				scanner_add_port( proto: proto, port: port );
			}
		}
	}
}
if(n_ports == 0){
	log_message( port: 0, proto: "tcp", data: "Host does not have any TCP port open which is specified in port range" );
}
set_kb_item( name: "Host/scanned", value: TRUE );
set_kb_item( name: "Host/scanners/pnscan", value: TRUE );
if(pr2 == "1:65535"){
	set_kb_item( name: "Host/full_scan", value: TRUE );
}
scanner_status( current: 65535, total: 65535 );
exit( 0 );

