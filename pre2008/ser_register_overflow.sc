if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11965" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "SIP Express Router Register Buffer Overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Noam Rathaus" );
	script_family( "Buffer overflow" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	script_xref( name: "URL", value: "http://www.iptel.org/ser/security/secalert-002-0_8_10.patch" );
	script_xref( name: "URL", value: "http://www.iptel.org/ser/security/" );
	script_tag( name: "solution", value: "Upgrade to version 0.8.11 or use the patch provided at
  the linked references." );
	script_tag( name: "summary", value: "The remote host is running a SIP Express Router.

  A bug has been found in the remote device which may allow an attacker to
  crash this device by sending a too long contact list in REGISTERs." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
if(!banner = sip_get_banner( port: port, proto: proto )){
	exit( 0 );
}
if(egrep( pattern: "Sip EXpress router .(0\\.[0-7]\\.|0\\.8\\.[0-9]|0\\.8\\.10) ", string: banner, icase: TRUE )){
	security_message( port: port, protocol: proto );
	exit( 0 );
}
exit( 99 );

