if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10716" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_cve_id( "CVE-2001-0778" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2788 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "OmniPro HTTPd 2.08 scripts source full disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2001 INTRANODE" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_omnihttpd_detect.sc" );
	script_mandatory_keys( "omnihttpd/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "OmniPro HTTPd 2.08 suffers from a security vulnerability that permits
  malicious users to get the full source code of scripting files." );
	script_tag( name: "insight", value: "By appending an ASCII/Unicode space char '%20' at the script suffix,
  the web server will no longer interpret it and rather send it back clearly
  as a simple document to the user in the same manner as it usually does to
  process HTML-like files.

  The flaw does not work with files located in CGI directories (e.g cgibin,
  cgi-win)

  Exploit: GET /test.php%20 HTTP/1.0" );
	script_tag( name: "affected", value: "Up to release 2.08" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
CPE = "cpe:/a:omnicron:omnihttpd";
require("host_details.inc.sc");
require("http_func.inc.sc");
func check( poison, port ){
	soc = http_open_socket( port );
	if(!soc){
		return ( 0 );
	}
	request = http_get( item: poison, port: port );
	send( socket: soc, data: request );
	response = http_recv( socket: soc );
	http_close_socket( soc );
	regex_signature[2] = "<?";
	if( ContainsString( response, regex_signature[2] ) ) {
		return ( 1 );
	}
	else {
		return ( 0 );
	}
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
Egg = "%20 ";
signature = "test.php";
poison = NASLString( "/", signature, Egg );
if(check( poison: poison, port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

