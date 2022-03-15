if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141956" );
	script_version( "2021-09-29T05:25:13+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-04 15:09:35 +0700 (Mon, 04 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "UBNT Discovery Protocol Amplification Attack" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ubnt_discovery_protocol_detect.sc", "global_settings.sc" );
	script_mandatory_keys( "ubnt_discovery_proto/detected", "keys/is_public_addr" );
	script_tag( name: "summary", value: "A publicly accessible Ubiquity device exposing the UBNT
  Discovery Protocol can be exploited to participate in a Distributed Denial of Service (DDoS)
  attack." );
	script_tag( name: "insight", value: "There are reports that there are ongoing attacks against devices
  with UBNT Discovery Protocol reachable which either result in a loss of device management or are
  used as a weak DDoS amplificatior.

  The basic attack technique consists of an attacker sending a valid query request to a UBNT server
  with the source address spoofed to be the victim's address. Since UBNT Discovery Protocol uses UDP
  this is trivialy done. When the UBNT server sends the response, it is sent instead to the victim.
  Because the size of the response is typically considerably larger than the request, the attacker
  is able to amplify the volume of traffic directed at the victim (the amplification factor is
  around 30-35x). By leveraging a botnet to perform additional spoofed queries, an attacker can
  produce an overwhelming amount of traffic with little effort." );
	script_tag( name: "vuldetect", value: "Checks if the UBNT Discovery Protocol is publicly reachable.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)" );
	script_tag( name: "solution", value: "Ubiquiti recommends to block port 10001/udp at the perimeter." );
	script_xref( name: "URL", value: "https://twitter.com/troutman/status/1090212243197870081" );
	script_xref( name: "URL", value: "https://community.ubnt.com/t5/airMAX-General-Discussion/Possible-Exploit-Losing-access-to-SSH-and-HTTP-HTTPS-on-CPEs/td-p/2411064" );
	script_xref( name: "URL", value: "https://community.ubnt.com/t5/airMAX-General-Discussion/airOS-airMAX-and-management-access/td-p/2654023" );
	script_xref( name: "URL", value: "https://www.us-cert.gov/ncas/alerts/TA14-017A" );
	script_xref( name: "URL", value: "https://blog.rapid7.com/2019/02/01/ubiquiti-discovery-service-exposures/" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("network_func.inc.sc");
if(!is_public_addr()){
	exit( 0 );
}
if(!port = service_get_port( default: 10001, ipproto: "udp", proto: "ubnt_discovery" )){
	exit( 0 );
}
security_message( data: "The UBNT Discovery Protocol is reachable over this port which might be used as a DDoS " + "amplifier.", port: port, proto: "udp" );
exit( 0 );

