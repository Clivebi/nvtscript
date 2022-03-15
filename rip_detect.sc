if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11822" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "RIP detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_require_udp_ports( 520 );
	script_tag( name: "summary", value: "This plugin detects RIP-1 and RIP-2 agents and display
  their routing tables." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
func rip_test( port, priv ){
	var soc, req, r, l, ver, report, i, n, ip_addr, mask, metric, next_hop, kbd, fam;
	if( priv ){
		soc = open_priv_sock_udp( dport: port, sport: port );
	}
	else {
		soc = open_sock_udp( port );
	}
	if(!soc){
		return FALSE;
	}
	r = "";
	for(v = 2;v >= 1 && strlen( r ) == 0;v--){
		req = raw_string( 1, v, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16 );
		send( socket: soc, data: req );
		r = recv( socket: soc, length: 512, timeout: 3 );
	}
	close( soc );
	l = strlen( r );
	if(l < 4 || ord( r[0] ) != 2){
		return FALSE;
	}
	ver = ord( r[1] );
	if(ver != 1 && ver != 2){
		return FALSE;
	}
	set_kb_item( name: "/rip/" + port + "/version", value: ver );
	report = strcat( "A RIP-", ver, " agent is running on this port.\n" );
	n = 0;
	for(i = 4;i < l;i += 20){
		fam = 256 * ord( r[i] ) + ord( r[i + 1] );
		if( fam == 2 ){
			ip_addr = strcat( ord( r[i + 4] ), ".", ord( r[i + 5] ), ".", ord( r[i + 6] ), ".", ord( r[i + 7] ) );
			mask = strcat( ord( r[i + 8] ), ".", ord( r[i + 9] ), ".", ord( r[i + 10] ), ".", ord( r[i + 11] ) );
			nexthop = strcat( ord( r[i + 12] ), ".", ord( r[i + 13] ), ".", ord( r[i + 14] ), ".", ord( r[i + 15] ) );
			metric = ord( r[i + 19] ) + 256 * ( ord( r[i + 18] ) + 256 * ( ord( r[i + 17] ) + 256 * ord( r[i + 16] ) ) );
			if(n == 0){
				report += "The following routes are advertised:\n";
			}
			n++;
			kbd = strcat( "/routes/", n );
			set_kb_item( name: kbd + "/addr", value: ip_addr );
			if( ver == 1 ){
				report += ip_addr;
			}
			else {
				report = strcat( report, ip_addr, "/", mask );
				set_kb_item( name: kbd + "/mask", value: mask );
			}
			if( metric == 16 ){
				report += " at infinity";
			}
			else {
				if( metric <= 1 ){
					report = strcat( report, " at ", metric, " hop" );
				}
				else {
					report = strcat( report, " at ", metric, " hops" );
				}
			}
			set_kb_item( name: kbd + "/metric", value: metric );
			if(ver > 1 && nexthop != "0.0.0.0"){
				report = strcat( report, ", next hop at ", nexthop );
				set_kb_item( name: kbd + "/nexthop", value: nexthop );
			}
			report += "\n";
		}
		else {
			}
	}
	if(n > 0){
		report += "This information on your network topology may help an attacker\n";
	}
	set_kb_item( name: "RIP/detected", value: TRUE );
	log_message( port: port, data: report, protocol: "udp" );
	service_register( port: port, ipproto: "udp", proto: "rip" );
	if( ver == 1 ){
		set_kb_item( name: "RIP-1/enabled", value: TRUE );
	}
	else {
		if(!islocalnet()){
			set_kb_item( name: "RIP-2/enabled", value: TRUE );
		}
	}
	return TRUE;
}
port = 520;
if(!get_udp_port_state( port )){
	exit( 0 );
}
if(rip_test( port: port, priv: FALSE )){
	exit( 0 );
}
if(rip_test( port: port, priv: TRUE )){
	report = "This RIP agent is broken: it only answers to requests where the source";
	report += " port is set to 520. This is not RFC compliant, but does not have security consequences.";
	log_message( port: port, protocol: "udp", data: report );
	set_kb_item( name: "/rip/" + port + "/broken_source_port", value: TRUE );
}
exit( 0 );
