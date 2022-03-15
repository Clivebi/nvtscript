if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14683" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 1249 );
	script_xref( name: "OSVDB", value: "1353" );
	script_cve_id( "CVE-2000-0360" );
	script_name( "INN buffer overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Buffer overflow" );
	script_dependencies( "nntpserver_detect.sc" );
	script_require_ports( "Services/nntp", 119 );
	script_mandatory_keys( "nntp/detected" );
	script_tag( name: "solution", value: "Upgrade to version 2.2.2 or later." );
	script_tag( name: "summary", value: "The remote version of this INN (InterNetNews) server
  does not do proper bounds checking." );
	script_tag( name: "impact", value: "An attacker may exploit this issue to crash the remote
  service by overflowing some of the buffers by sending a maliciously formatted news article." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("nntp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = nntp_get_port( default: 119 );
banner = get_kb_item( "nntp/banner/" + port );
if(!banner || !ContainsString( banner, "INN" )){
	exit( 0 );
}
if(egrep( string: banner, pattern: "^20[0-9] .* INN 2\\.(([01]\\..*)|(2\\.[01][^0-9])) .*$" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

