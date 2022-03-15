if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80066" );
	script_version( "$Revision: 10411 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ICMP domain name request" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>" );
	script_family( "Service detection" );
	script_dependencies( "global_settings.sc" );
	script_exclude_keys( "keys/islocalhost", "keys/TARGET_IS_IPV6" );
	script_xref( name: "URL", value: "http://www.ietf.org/rfc/rfc1788.txt" );
	script_tag( name: "solution", value: "If you do not use this feature, filter out incoming ICMP packets
  of type 37 and outgoing ICMP packets of type 38." );
	script_tag( name: "summary", value: "The remote host answered to an ICMP 'Domain Name Request'
  as defined in RFC 1788.

  Such a request is designed to obtain the DNS name of a host
  based on its IP." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
if(islocalhost()){
	exit( 0 );
}
max = 2;
func extract_dns_data( dns ){
	var v, vi, l, i, s, n, i1, n1, out;
	v = NULL;
	vi = 0;
	l = strlen( dns );
	i = 0;
	for(;i < l;){
		s = "";
		for(;i < l;){
			n = ord( dns[i++] );
			if(n == 0){
				break;
			}
			if( ( n & 0xC0 ) == 0xC0 ){
				i1 = ( n & 0x3F ) << 8 | ord( dns[i++] );
				n1 = ord( dns[i1++] );
				if(i1 + n1 >= l){
					break;
				}
				if( n1 & 0xC0 == 0xC0 ) {
					display( "icmp_domain_name.nasl: ", get_host_ip(), " returned a packet with chained DNS compression\n" );
				}
				else {
					s = strcat( s, substr( dns, i1, i1 + n1 - 1 ), "." );
				}
			}
			else {
				if(i + n > l){
					break;
				}
				s = strcat( s, substr( dns, i, i + n - 1 ), "." );
			}
			i += n;
		}
		v[vi++] = s;
	}
	out = "";
	for(i = 0;i < vi;i++){
		out = strcat( out, v[i], "\n" );
	}
	return out;
}
ip = forge_ip_packet( ip_hl: 5, ip_v: 4, ip_off: 0, ip_tos: 0, ip_p: IPPROTO_ICMP, ip_len: 20, ip_src: this_host(), ip_ttl: 255 );
icmp = forge_icmp_packet( ip: ip, icmp_type: 37, icmp_code: 0, icmp_seq: 1, icmp_id: 1 );
filter = NASLString( "icmp and src host ", get_host_ip(), " and dst host ", this_host(), " and icmp[0] = 38" );
for(i = 0;i < max;i++){
	r = send_packet( packet: icmp, pcap_active: TRUE, pcap_filter: filter, pcap_timeout: 1 );
	if(!isnull( r )){
		type = get_icmp_element( icmp: r, element: "icmp_type" );
		if(type == 38){
			hl = ( ord( r[0] ) & 0x0F ) * 4;
			data = substr( r, hl + 12 );
			output = extract_dns_data( dns: data );
			if( output ) {
				log_message( protocol: "icmp", port: 0, data: output );
			}
			else {
				log_message( protocol: "icmp", port: 0 );
			}
			set_kb_item( name: "icmp/domain_name", value: TRUE );
		}
		exit( 0 );
	}
}

