CPE = "cpe:/a:memcached:memcached";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108357" );
	script_version( "2021-09-29T05:25:13+0000" );
	script_cve_id( "CVE-2018-1000115" );
	script_tag( name: "last_modification", value: "2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-03-01 08:31:24 +0100 (Thu, 01 Mar 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Memcached Amplification Attack (Memcrashed)" );
	script_category( ACT_ATTACK );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_memcached_detect_udp.sc", "global_settings.sc" );
	script_require_udp_ports( "Services/udp/memcached", 11211 );
	script_mandatory_keys( "memcached/udp/detected", "keys/is_public_addr" );
	script_xref( name: "URL", value: "https://github.com/memcached/memcached/wiki/ReleaseNotes156" );
	script_xref( name: "URL", value: "https://blogs.akamai.com/2018/02/memcached-udp-reflection-attacks.html" );
	script_xref( name: "URL", value: "https://www.arbornetworks.com/blog/asert/memcached-reflection-amplification-description-ddos-attack-mitigation-recommendations/" );
	script_xref( name: "URL", value: "https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/" );
	script_tag( name: "summary", value: "A publicly accessible Memcached server can be exploited to
  participate in a Distributed Denial of Service (DDoS) attack." );
	script_tag( name: "vuldetect", value: "Sends a crafted UDP request and checks the response.

  Note:

  This VT is only reporting a vulnerability if the target system / service is accessible from a
  public WAN (Internet) / public LAN.

  A configuration option 'Network type' to define if a scanned network should be seen as a public
  LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)" );
	script_tag( name: "insight", value: "An Amplification attack is a popular form of Distributed Denial
  of Service (DDoS) that relies on the use of publicly accessible Memcached servers to overwhelm a
  victim system with response traffic.

  The basic attack technique consists of an attacker sending a valid query request to a Memcached
  server with the source address spoofed to be the victim's address. When the Memcached server sends
  the response, it is sent instead to the victim. Attackers will typically first inserting records
  into the open server to maximize the amplification effect. Because the size of the response is
  typically considerably larger than the request, the attacker is able to amplify the volume of
  traffic directed at the victim. By leveraging a botnet to perform additional spoofed queries, an
  attacker can produce an overwhelming amount of traffic with little effort. Additionally, because
  the responses are legitimate data coming from valid clients, it is especially difficult to block
  these types of attacks." );
	script_tag( name: "solution", value: "The following mitigation possibilities are currently available:

  - Disable public access to the UDP port of this Memcached server.

  - Configure Memcached to only listen on localhost by specifying '--listen 127.0.0.1' on server
  startup.

  - Disable the UDP protocol by specifying '-U 0' on server startup.

  - Update to Memcached to 1.5.6 which disables the UDP protocol by default." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("network_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
if(!is_public_addr()){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_location_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
proto = infos["proto"];
if(proto != "udp"){
	exit( 0 );
}
if(!soc = open_sock_udp( port )){
	exit( 0 );
}
data = raw_string( 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 );
data += NASLString( "stats\\r\\n" );
req_len = strlen( data );
send( socket: soc, data: data );
res = recv( socket: soc, length: 4096 );
close( soc );
if(!res || strlen( res ) < 8){
	exit( 0 );
}
res_str = bin2string( ddata: res, noprint_replacement: " " );
if(!IsMatchRegexp( hexstr( substr( res, 0, 7 ) ), "^([0-9]+)" ) || !IsMatchRegexp( res_str, "STAT " )){
	exit( 0 );
}
resp_len = strlen( res );
if(resp_len > ( 20 * req_len )){
	report = "We have sent a query request of " + req_len + " bytes and received a response of " + resp_len + " bytes.";
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

