if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11913" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 10411 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "DCN HELLO detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "global_settings.sc" );
	script_exclude_keys( "keys/islocalhost", "keys/TARGET_IS_IPV6" );
	script_tag( name: "summary", value: "The remote IP stack answers to an obsolete protocol.

  Description :

  The remote host is running HELLO, an obsolete routing protocol.
  If possible, this IP protocol should be disabled." );
	script_tag( name: "solution", value: "If this protocol is not needed, disable it or filter incoming traffic going
  to IP protocol #63." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("network_func.inc.sc");
if(TARGET_IS_IPV6()){
	exit( 0 );
}
if(islocalhost()){
	exit( 0 );
}
s = this_host();
v = eregmatch( pattern: "^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9])+$", string: s );
if(isnull( v )){
	exit( 0 );
}
for(i = 1;i <= 4;i++){
	a[i] = int( v[i] );
}
a1 = rand() % 256;
a2 = rand() % 256;
s1 = rand() % 256;
s2 = rand() % 256;
ms = ms_since_midnight();
if(isnull( ms )){
	ms = rand();
}
r = raw_string( 0, 0, 0xF3, 0xFF );
r += htons( n: ms );
r += raw_string( 0, 0, 0, 0 );
ck = ip_checksum( data: r );
r2 = insstr( r, ck, 0, 1 );
egp = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_p: 63, ip_ttl: 64, ip_off: 0, ip_src: this_host(), data: r2 );
f = "ip proto 63 and src " + get_host_ip();
for(i = 0;i < 3;i++){
	r = send_packet( packet: egp, pcap_active: TRUE, pcap_filter: f, pcap_timeout: 1 );
	if(r){
		break;
	}
}
if(isnull( r )){
	exit( 99 );
}
log_message( port: 0, proto: "hello" );
exit( 0 );

