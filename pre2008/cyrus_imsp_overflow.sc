if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11953" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_bugtraq_id( 9227 );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "cyrus-imsp abook_dbname buffer overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Noam Rathaus" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/imsp", 406 );
	script_tag( name: "solution", value: "Upgrade cyrus-imsp server to version version 1.6a4 or 1.7a." );
	script_tag( name: "summary", value: "The remote host is running a version of cyrus-imsp (Internet Message Support
  Protocol) which has a buffer overflow bug." );
	script_tag( name: "impact", value: "An attacker could exploit this bug to execute arbitrary code on this system
  with the privileges of the root user." );
	script_tag( name: "insight", value: "The overflow occurs when the user issues a too long argument as his name,
  causing an overflow in the abook_dbname function command." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 406, proto: "imsp" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
banner = recv_line( socket: soc, length: 4096 );
close( soc );
if(banner && ereg( pattern: ".* Cyrus IMSP version (0\\..*|1\\.[0-5]|1\\.6|1\\.6a[0-3]|1\\.7) ready", string: banner )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

