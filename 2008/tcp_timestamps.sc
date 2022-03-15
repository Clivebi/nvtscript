if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80091" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_name( "TCP timestamps" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2008 Michel Arboi" );
	script_dependencies( "secpod_open_tcp_ports.sc", "global_settings.sc" );
	script_mandatory_keys( "TCP/PORTS" );
	script_exclude_keys( "keys/islocalhost", "keys/TARGET_IS_IPV6" );
	script_add_preference( name: "Delay (seconds):", value: "1", type: "entry", id: 1 );
	script_xref( name: "URL", value: "http://www.ietf.org/rfc/rfc1323.txt" );
	script_xref( name: "URL", value: "http://www.ietf.org/rfc/rfc7323.txt" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20151213072445/http://www.microsoft.com/en-us/download/details.aspx?id=9152" );
	script_tag( name: "summary", value: "The remote host implements TCP timestamps and therefore allows to compute
  the uptime." );
	script_tag( name: "vuldetect", value: "Special IP packets are forged and sent with a little delay in between to the
  target IP. The responses are searched for a timestamps. If found, the timestamps are reported." );
	script_tag( name: "solution", value: "To disable TCP timestamps on linux add the line 'net.ipv4.tcp_timestamps = 0' to
  /etc/sysctl.conf. Execute 'sysctl -p' to apply the settings at runtime.

  To disable TCP timestamps on Windows execute 'netsh int tcp set global timestamps=disabled'

  Starting with Windows Server 2008 and Vista, the timestamp can not be completely disabled.

  The default behavior of the TCP/IP stack on this Systems is to not use the
  Timestamp options when initiating TCP connections, but use them if the TCP peer
  that is initiating communication includes them in their synchronize (SYN) segment.

  See the references for more information." );
	script_tag( name: "affected", value: "TCP implementations that implement RFC1323/RFC7323." );
	script_tag( name: "insight", value: "The remote host implements TCP timestamps, as defined by RFC1323/RFC7323." );
	script_tag( name: "impact", value: "A side effect of this feature is that the uptime of the remote
  host can sometimes be computed." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("network_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
if(TARGET_IS_IPV6()){
	exit( 0 );
}
if(islocalhost()){
	exit( 0 );
}
debug = FALSE;
func test( seq, saddr, daddr, dport ){
	var seq, saddr, daddr, dport;
	var sport, ip, options, tcp, filter, r, ms, tsval;
	sport = rand() % ( 65536 - 1024 ) + 1024;
	ip = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_len: 20, ip_id: rand(), ip_p: IPPROTO_TCP, ip_ttl: 255, ip_off: 0, ip_src: saddr );
	options = strcat( "\x08", "\x0A", htonl( n: seq ), "\0\0\0\0", "\x01\x01" );
	tcp = forge_tcp_packet( ip: ip, th_sport: sport, th_dport: dport, th_flags: TH_SYN, th_seq: rand(), th_ack: 0, th_x2: 0, th_off: 8, th_win: 512, th_urp: 0, data: options );
	filter = strcat( "tcp and src ", daddr, " and dst ", saddr, " and src port ", dport, " and dst port ", sport );
	r = send_packet( packet: tcp, pcap_active: TRUE, pcap_filter: filter );
	if(isnull( r )){
		return NULL;
	}
	ms = ms_since_midnight();
	tsval = tcp_extract_option_field( ip: r, option: "Timestamp", debug: debug );
	if(isnull( tsval )){
		return NULL;
	}
	return make_list( ms,
		 tsval );
}
delay = script_get_preference( name: "Delay (seconds):", id: 1 );
if(!delay || int( delay ) < 1){
	delay = 1;
}
dport = tcp_get_first_open_port();
saddr = this_host();
daddr = get_host_ip();
v1 = test( seq: 1, daddr: daddr, saddr: saddr, dport: dport );
if(isnull( v1 )){
	exit( 0 );
}
sleep( delay );
v2 = test( seq: 2, daddr: daddr, saddr: saddr, dport: dport );
if(isnull( v2 )){
	exit( 0 );
}
dms = v2[0] - v1[0];
dseq = v2[1] - v1[1];
result = "It was detected that the host implements RFC1323/RFC7323.";
if(v2[1] > 0){
	result += "\n\nThe following timestamps were retrieved with a delay of " + delay + " seconds in-between:\n" + "Packet 1: " + v1[1] + "\n" + "Packet 2: " + v2[1];
}
security_message( data: result );
exit( 0 );

