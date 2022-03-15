if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11170" );
	script_version( "2020-11-09T15:55:00+0000" );
	script_tag( name: "last_modification", value: "2020-11-09 15:55:00 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6220 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2002-1272" );
	script_name( "Alcatel OmniSwitch 7700/7800 switches backdoor" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 deepquest" );
	script_family( "Malware" );
	script_dependencies( "find_service.sc", "telnet.sc" );
	script_require_ports( 6778 );
	script_xref( name: "URL", value: "http://www.cert.org/advisories/CA-2002-32.html" );
	script_tag( name: "solution", value: "Block access to port 6778/TCP or update to
  AOS 5.1.1.R02 or AOS 5.1.1.R03." );
	script_tag( name: "summary", value: "The remote host seems to be a backdoored
  Alcatel OmniSwitch 7700/7800." );
	script_tag( name: "impact", value: "An attacker can gain full access to any device
  running AOS version 5.1.1, which can result in, but is not limited to,
  unauthorized access, unauthorized monitoring, information leakage,
  or denial of service." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
require("port_service_func.inc.sc");
port = 6778;
if(!service_verify( port: port, proto: "telnet" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
data = telnet_get_banner( port: port );
telnet_close_socket( socket: soc, data: data );
if(data){
	security_message( port: port, data: "Banner:\n" + data );
	exit( 0 );
}
exit( 99 );

