if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10811" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3526 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0815" );
	script_name( "ActivePerl perlIS.dll Buffer Overflow" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/banner" );
	script_tag( name: "solution", value: "Either upgrade to a version of ActivePerl more
  recent than 5.6.1.629 or enable the Check that file exists option.

  To enable this option, open up the IIS MMC, right click on a (virtual) directory in
  your web server, choose Properties, click on the Configuration... button, highlight
  the .plx item, click Edit, and then check Check that file exists." );
	script_tag( name: "summary", value: "An attacker can run arbitrary code on the remote computer.

  This is because the remote IIS server is running a version of ActivePerl prior to 5.6.1.630
  and has the Check that file exists option disabled for the perlIS.dll." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
sig = http_get_remote_headers( port: port );
if(!sig || !ContainsString( sig, "IIS" )){
	exit( 0 );
}
func check( url ){
	req = http_get( item: url, port: port );
	r = http_keepalive_send_recv( port: port, data: req );
	if(!r){
		return ( 0 );
	}
	if(ContainsString( r, "HTTP/1.1 500 Server Error" ) && ( ContainsString( r, "The remote procedure call failed." ) || ContainsString( r, "<html><head><title>Error</title>" ) )){
		security_message( port: port );
		return ( 1 );
	}
	return ( 0 );
}
for dir in make_list( "/scripts/",
	 "/cgi-bin/",
	 "/" ) {
	url = NASLString( dir, crap( 660 ), ".plx" );
	if(check( req: url )){
		exit( 0 );
	}
	url = NASLString( dir, crap( 660 ), ".pl" );
	if(check( req: url )){
		exit( 0 );
	}
}
exit( 99 );

