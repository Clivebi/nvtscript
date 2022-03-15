if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11894" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2003-1510" );
	script_bugtraq_id( 8810 );
	script_name( "TinyWeb 1.9" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Matt North" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "TinyWeb/banner" );
	script_tag( name: "solution", value: "Contact the Vendor for an update." );
	script_tag( name: "summary", value: "The remote host is running TinyWeb version 1.9 or older." );
	script_tag( name: "impact", value: "A remote user can issue an HTTP GET request for
  /cgi-bin/.%00./dddd.html and cause the server consume large amounts of CPU time (88%-92%)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banbanner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "TinyWeb" )){
	exit( 0 );
}
if(egrep( pattern: "^Server:.*TinyWeb/(0\\..*|1\\.[0-9]([^0-9]|$))", string: banner )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

