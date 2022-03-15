if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103718" );
	script_version( "2021-09-29T05:25:13+0000" );
	script_cve_id( "CVE-2006-0987" );
	script_tag( name: "last_modification", value: "2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-05-28 11:31:19 +0200 (Tue, 28 May 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "DNS Amplification Attacks (UDP)" );
	script_category( ACT_ATTACK );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "dns_server.sc", "global_settings.sc" );
	script_require_udp_ports( "Services/udp/domain", 53 );
	script_mandatory_keys( "DNS/identified", "keys/is_public_addr" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/ncas/alerts/TA13-088A" );
	script_xref( name: "URL", value: "http://www.isotf.org/news/DNS-Amplification-Attacks.pdf" );
	script_tag( name: "summary", value: "A misconfigured Domain Name System (DNS) server can be exploited
  to participate in a Distributed Denial of Service (DDoS) attack." );
	script_tag( name: "vuldetect", value: "Sends a crafted UDP request and checks the response.

  Note:

  This VT is only reporting a vulnerability if the target system / service is accessible from a
  public WAN (Internet) / public LAN.

  A configuration option 'Network type' to define if a scanned network should be seen as a public
  LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)" );
	script_tag( name: "insight", value: "A Domain Name Server (DNS)Amplification attack is a popular form
  of Distributed Denial of Service (DDoS) that relies on the use of publicly accessible open
  recursive DNS servers to overwhelm a victim system with DNS response traffic.

  The basic attack technique consists of an attacker sending a DNS name lookup request to an open
  recursive DNS server with the source address spoofed to be the victim's address. When the DNS
  server sends the DNS record response, it is sent instead to the victim. Attackers will typically
  submit a request for as much zone information as possible to maximize the amplification effect.
  Because the size of the response is typically considerably larger than the request, the attacker
  is able to amplify the volume of traffic directed at the victim. By leveraging a botnet to perform
  additional spoofed DNS queries, an attacker can produce an overwhelming amount of traffic with
  little effort. Additionally, because the responses are legitimate data coming from valid servers,
  it is especially difficult to block these types of attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("network_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(!is_public_addr()){
	exit( 0 );
}
port = service_get_port( default: 53, proto: "domain", ipproto: "udp" );
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
data = raw_string( 0x80, 0xa5, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01 );
req_len = strlen( data );
send( socket: soc, data: data );
buf = recv( socket: soc, length: 4096 );
close( soc );
resp_len = strlen( buf );
if(buf && resp_len > ( 2 * req_len )){
	data = "We have sent a DNS request of " + req_len + " bytes and received a response of " + resp_len + " bytes.";
	security_message( port: port, data: data, proto: "udp" );
	exit( 0 );
}
exit( 99 );

