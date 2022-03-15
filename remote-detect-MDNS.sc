if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101013" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-03-16 00:46:49 +0100 (Mon, 16 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "MDNS Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele" );
	script_family( "Service detection" );
	script_require_udp_ports( "Services/udp/mdns", 5353 );
	script_tag( name: "solution", value: "It's recommended to disable this service if not used." );
	script_tag( name: "summary", value: "The Remote Host is Running the MDNS Service.
  Zeroconf, or Zero Configuration Networking, often known as MDNS or Bonjour/rendez-vous,
  is a set of techniques that automatically create a usable IP network without configuration or special servers." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("dump.inc.sc");
func grabHostInfos( stringa ){
	var stringa, length, stradds, pad, addr, na, nb, n, hostname, infos;
	if(strlen( stringa ) < 51){
		return;
	}
	length = ord( stringa[51] ) * 256 + ord( stringa[52] ) - 1;
	straddr = substr( stringa, 54, 51 + length );
	pad = split( buffer: straddr, sep: "[" );
	addr = str_replace( string: pad[1], find: "]", replace: "" );
	na = str_replace( string: pad[0], find: raw_string( 0xe2, 0x80, 0x99 ), replace: "" );
	nb = str_replace( string: na, find: "\\ ", replace: "-" );
	n = str_replace( string: nb, find: "\\'", replace: "" );
	hostname = eregmatch( pattern: "([^ ]+)", string: n );
	infos = make_array( 0, addr, 1, hostname[0] );
	return ( infos );
}
func grabCpuInfos( stringa ){
	var stringa, offset, cpu_len, mn, mj, cpu_type, minor, major, pados, os, os_x, infos;
	if(strlen( stringa ) < 11){
		return;
	}
	offset = 13 + ord( stringa[12] ) + 23;
	cpu_len = ord( stringa[offset] );
	mn = offset + 1;
	mj = mn + cpu_len;
	cpu_type = substr( stringa, mn, mj );
	offset += cpu_len + 1;
	minor = offset + 1;
	major = minor + ord( stringa[offset] );
	pados = substr( stringa, minor, major );
	os = split( buffer: pados, sep: ";" );
	os_x = os[0];
	infos = make_array( 0, cpu_type, 1, os_x );
	return ( infos );
}
func createMDNSQuery( query, itype ){
	var query, itype, pkt1, pkt2, length, element;
	pkt2 = "";
	pkt1 = raw_string( 0x00, 0x4a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
	for element in query {
		length = strlen( element );
		pkt1 += raw_string( length ) + element;
	}
	if(itype == "PTR"){
		pkt1 += raw_string( 0x00, 0x00, 0x0c, 0x00, 0x01 );
	}
	if(itype == "HINFO"){
		for element in query {
			pkt1 = pkt1 + raw_string( 0x00, 0x0d, 0x00, 0x01, 0x00 );
			return ( pkt1 );
		}
	}
	return ( pkt1 );
}
port = service_get_port( default: 5353, ipproto: "udp", proto: "mdns" );
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
qry1 = make_list( "_daap",
	 "_tcp",
	 "local" );
qry2 = make_list( "_workstation",
	 "_tcp",
	 "local" );
pkt1 = createMDNSQuery( query: qry1, itype: "PTR" );
pkt2 = createMDNSQuery( query: qry2, itype: "PTR" );
send( socket: soc, data: pkt1 );
send( socket: soc, data: pkt2 );
reply = recv( socket: soc, length: 1024 );
if(reply){
	hostinfos = grabHostInfos( stringa: reply );
	if(NASLTypeof( hostinfos ) == "array"){
		qry3 = make_list( hostinfos[1],
			 "local",
			 "" );
		pkt3 = createMDNSQuery( query: qry3, itype: "HINFO" );
		send( socket: soc, data: pkt3 );
		reply = recv( socket: soc, length: 1 );
		reply = recv( socket: soc, length: 1024 );
		cpuinfos = grabCpuInfos( stringa: reply );
	}
	service_register( port: port, ipproto: "udp", proto: "mdns" );
}
close( soc );
report = "";
if(strlen( hostinfos[1] ) > 1){
	hostname = hostinfos[1];
	report += "Hostname: " + hostname;
	set_kb_item( name: "MDNS/Host/hostname", value: hostname );
}
if(strlen( hostinfos[0] ) > 1){
	mac_address = hostinfos[0];
	report += " \nMAC Address: " + mac_address;
	set_kb_item( name: "MDNS/Host/MacAddress", value: mac_address );
	register_host_detail( name: "MAC", value: mac_address, desc: "MDNS Service Detection" );
}
if(strlen( cpuinfos[0] ) > 1){
	cpu_type = cpuinfos[0];
	report += "\nCPU Type: " + cpu_type;
	set_kb_item( name: "MDNS/Host/CpuType", value: cpu_type );
}
if(strlen( cpuinfos[1] ) > 1){
	operating_system = cpuinfos[1];
	report += "\nOperating System: " + operating_system;
	set_kb_item( name: "MDNS/Host/OS", value: operating_system );
	if( ContainsString( tolower( operating_system ), "linux" ) ){
		os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner: operating_system, banner_type: "MDNS banner", port: port, proto: "udp", desc: "MDNS Service Detection", runs_key: "unixoide" );
	}
	else {
		if( ContainsString( tolower( operating_system ), "windows" ) ){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner: operating_system, banner_type: "MDNS banner", port: port, proto: "udp", desc: "MDNS Service Detection", runs_key: "windows" );
		}
		else {
			if( ContainsString( tolower( operating_system ), "mac os x" ) ){
				os_register_and_report( os: "Mac OS X", cpe: "cpe:/o:apple:mac_os_x", banner: operating_system, banner_type: "MDNS banner", port: port, proto: "udp", desc: "MDNS Service Detection", runs_key: "unixoide" );
			}
			else {
				os_register_unknown_banner( banner: operating_system, banner_type_name: "MDNS banner", banner_type_short: "mdns_banner", port: port, proto: "udp" );
			}
		}
	}
}
if(strlen( report )){
	log_message( port: port, data: report, protocol: "udp" );
}
exit( 0 );

