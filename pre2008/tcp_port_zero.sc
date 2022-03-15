if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18164" );
	script_version( "$Revision: 10411 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Port TCP:0 Open" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2005 Michel Arboi" );
	script_family( "Malware" );
	script_dependencies( "find_service.sc", "global_settings.sc" );
	script_exclude_keys( "keys/islocalhost", "keys/TARGET_IS_IPV6" );
	script_tag( name: "solution", value: "Check your system" );
	script_tag( name: "summary", value: "TCP port 0 is open on the remote host. This is highly suspicious as
  this TCP port is reserved and should not be used. This might be a backdoor (REx)." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(islocalhost()){
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
saddr = this_host();
daddr = get_host_ip();
sport = rand() % 64512 + 1024;
dport = 0;
filter = strcat( "src port ", dport, " and src host ", daddr, " and dst port ", sport, " and dst host ", saddr );
ip = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_off: 0, ip_len: 20, ip_p: IPPROTO_TCP, ip_ttl: 0x40, ip_src: saddr );
tcp = forge_tcp_packet( ip: ip, th_sport: sport, th_dport: dport, th_flags: TH_SYN, th_seq: rand(), th_ack: 0, th_x2: 0, th_off: 5, th_win: 512, th_urp: 0 );
for(i = 0;i < 3;i++){
	reply = send_packet( pcap_active: TRUE, pcap_filter: filter, pcap_timeout: 2, packet:tcp );
	if(reply){
		flags = get_tcp_element( tcp: reply, element: "th_flags" );
		if(( flags & TH_SYN ) && ( flags & TH_ACK )){
			security_message( port: 0 );
		}
		exit( 0 );
	}
}

