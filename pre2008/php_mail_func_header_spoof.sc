if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11444" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5562 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0985", "CVE-2002-0986" );
	script_name( "PHP Mail Function Header Spoofing Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2002 tony@libpcap.net" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "PHP/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Contact your vendor for the latest PHP release." );
	script_tag( name: "summary", value: "The remote host is running a version of PHP <= 4.2.2.

  The mail() function does not properly sanitize user input." );
	script_tag( name: "impact", value: "This allows users to forge email to make it look like it is
  coming from a different source other than the server.

  Users can exploit this even if SAFE_MODE is enabled." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "PHP" )){
	exit( 0 );
}
if(egrep( pattern: ".*PHP/([0-3]\\..*|4\\.[01]\\..*|4\\.2\\.[0-2][^0-9])", string: banner )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

