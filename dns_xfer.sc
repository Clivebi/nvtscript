if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10595" );
	script_version( "2021-05-14T13:11:51+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_cve_id( "CVE-1999-0532" );
	script_name( "DNS AXFR" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 j_lampe@bellsouth.net" );
	script_family( "Service detection" );
	script_dependencies( "dns_server_tcp.sc", "dns_server.sc", "msdns-server-hostname-disclosure.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_tag( name: "impact", value: "A zone transfer will allow the remote attacker to instantly
  populate a list of potential targets. In addition, companies often use a naming convention
  which can give hints as to a servers primary application (for instance, proxy.company.com,
  payroll.company.com, b2b.company.com, etc.).

  As such, this information is of great use to an attacker who may use it to gain information
  about the topology of your network and spot new targets." );
	script_tag( name: "solution", value: "Restrict DNS zone transfers to only the servers that
  absolutely need it." );
	script_tag( name: "summary", value: "The remote name server allows DNS zone transfers to be performed." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("global_settings.inc.sc");
require("dump.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
func myintstring_to_int( mychar ){
	myintrray = "0123456789";
	for(q = 0;q < 10;q++){
		if(myintrray[q] == mychar){
			return ( q + 48 );
		}
	}
}
get_host_by_addr = raw_string( 0xB8, 0x4C, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
myip = get_host_ip();
len = strlen( myip );
counter = 0;
temprray = make_array();
for(flag = len;flag > 0;flag = flag - 1){
	if( myip[flag - 1] == "." ){
		get_host_by_addr = get_host_by_addr + raw_string( counter );
		for(tcount = flag;tcount < flag + counter;tcount++){
			mcount = temprray[tcount];
			get_host_by_addr = get_host_by_addr + raw_string( mcount );
		}
		for(mu = 0;mu < 15;mu++){
			temprray[mu] = 0;
		}
		counter = 0;
	}
	else {
		temprray[flag - 1] = myintstring_to_int( mychar: myip[flag - 1] );
		counter++;
	}
}
get_host_by_addr = get_host_by_addr + raw_string( counter );
for(tcount = flag;tcount < flag + counter;tcount++){
	mcount = temprray[tcount];
	get_host_by_addr = get_host_by_addr + raw_string( mcount );
}
get_host_by_addr = get_host_by_addr + raw_string( 0x07, 0x69, 0x6E, 0x2D, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61 );
get_host_by_addr = get_host_by_addr + raw_string( 0x00, 0x00, 0x0C, 0x00, 0x01 );
func ntohs( s, o ){
	var ret_hi, ret_lo;
	ret_hi = ord( s[o] ) << 8;
	ret_lo = ord( s[o + 1] );
	return ( ret_hi + ret_lo );
}
func skiplabels( buf, buflen, jump ){
	var curlabel;
	for(;jump < buflen;){
		curlabel = ord( buf[jump] );
		if(curlabel == 0){
			jump += 1;
			return ( jump );
		}
		if(curlabel >= 0xc0){
			jump += 2;
			return ( jump );
		}
		jump += curlabel + 1;
	}
	return jump;
}
func fetchlabels( buf, buflen, jump, skip ){
	var curlabel, result, iter;
	iter = 10;
	result = "";
	for(;jump < buflen && iter > 0;){
		curlabel = ord( buf[jump] );
		if( curlabel == 0 ){
			if(debug_level){
				display( "debug: fetchlabels >>", result, "<< (len=", strlen( result ), ")\\n" );
			}
			return ( result );
		}
		else {
			if( curlabel < 0xc0 ){
				if(jump + curlabel + 1 > buflen){
					return ( NULL );
				}
				if( isnull( skip ) || skip <= 0 ) {
					result = strcat( result, substr( buf, jump, jump + curlabel ) );
				}
				else {
					skip -= 1;
				}
				jump += curlabel + 1;
			}
			else {
				iter -= 1;
				if(jump + 2 > buflen){
					return ( NULL );
				}
				jump = ntohs( s: buf, o: jump ) & 0x3fff;
			}
		}
	}
	return ( NULL );
}
port = service_get_port( default: 53, proto: "domain", ipproto: "udp" );
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: get_host_by_addr );
myreturn = recv( socket: soc, length: 4096 );
myretlen = strlen( myreturn );
if(debug_level){
	display( "debug: got UDP answer myretlen=", myretlen, "\\n" );
}
close( soc );
if(myretlen < 12){
	exit( 0 );
}
ancount = ntohs( s: myreturn, o: 6 );
if(ancount < 1){
	exit( 0 );
}
jump = 12;
if(debug_level > 1){
	fetchlabels( buf: myreturn, buflen: myretlen, jump: jump );
}
jump = skiplabels( buf: myreturn, buflen: myretlen, jump: jump );
jump += 4;
found_answer = 0;
for(theta = 0;( theta < ancount ) && ( jump < myretlen );theta++){
	if(debug_level > 1){
		fetchlabels( buf: myreturn, buflen: myretlen, jump: jump );
	}
	jump = skiplabels( buf: myreturn, buflen: myretlen, jump: jump );
	jump += 10;
	if(jump < myretlen){
		rtype = ntohs( s: myreturn, o: jump - 10 );
		rclass = ntohs( s: myreturn, o: jump - 8 );
		if(debug_level){
			display( "debug: UDP answer RR rtype=", rtype, " rclass=", rclass, "\\n" );
		}
		if(rtype == 12 && rclass == 1){
			found_answer = 1;
			break;
		}
		jump += ntohs( s: myreturn, o: jump - 2 );
	}
}
if(!found_answer){
	exit( 0 );
}
domain = fetchlabels( buf: myreturn, buflen: myretlen, jump: jump, skip: 1 );
if(isnull( domain ) || domain == ""){
	exit( 0 );
}
domain = bin2string( ddata: domain, noprint_replacement: "." );
pass_da_zone = strcat( raw_string( 0x68, 0xB3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ), domain, raw_string( 0x00, 0x00, 0xFC, 0x00, 0x01 ) );
len = strlen( pass_da_zone );
len_hi = len / 256;
len_lo = len % 256;
pass_da_zone = raw_string( len_hi, len_lo ) + pass_da_zone;
if(!get_port_state( port )){
	exit( 0 );
}
soctcp = open_sock_tcp( port );
if(!soctcp){
	exit( 0 );
}
send( socket: soctcp, data: pass_da_zone );
incoming = recv( socket: soctcp, length: 2 );
if(strlen( incoming ) < 2){
	exit( 0 );
}
len = ntohs( s: incoming, o: 0 );
if(debug_level){
	display( "debug: got TCP answer len=", len, "\\n" );
}
if(len < 0){
	exit( 0 );
}
if(len > 8){
	len = 8;
}
incoming = recv( socket: soctcp, length: len, min: len );
close( soctcp );
ancount = ntohs( s: incoming, o: 6 );
if(ancount >= 1){
	domain = ereg_replace( string: domain, pattern: "\t", replace: "" );
	domain = str_replace( string: domain, find: " ", replace: "" );
	report = NASLString( "It was possible to initiate a zone transfer for the domain '", domain, "'\\n" );
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

