if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100257" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-08-25 21:06:41 +0200 (Tue, 25 Aug 2009)" );
	script_bugtraq_id( 33585 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "NaviCOPA Web Server Remote Buffer Overflow and Source Code Information Disclosure Vulnerabilities" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "InterVations/banner" );
	script_tag( name: "summary", value: "NaviCOPA Web Server is prone to a remote buffer-overflow vulnerability
  and an information-disclosure vulnerability because the application fails to properly bounds-check or
  validate user-supplied input." );
	script_tag( name: "impact", value: "Successful exploits of the buffer-overflow issue may lead to the
  execution of arbitrary code in the context of the application or to denial-of-service conditions. Also,
  attackers can exploit the information-disclosure issue to retrieve arbitrary source code in the context
  of the webserver process. Information harvested may aid in further attacks." );
	script_tag( name: "affected", value: "NaviCOPA Web Server 3.01 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "The vendor reports that NaviCOPA 3.01, with a release date of February
  6, 2009, addresses this issue. Contact the vendor for details." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/33585" );
	script_xref( name: "URL", value: "http://www.navicopa.com/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/500626" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !egrep( pattern: "Server:.*InterVations", string: banner )){
	exit( 0 );
}
if( safe_checks() ){
	if(!version_date = eregmatch( pattern: "Version ([0-9.]+).*(200[0-9]+)", string: banner )){
		exit( 0 );
	}
	if(version_is_equal( version: version_date[1], test_version: "3.01" ) && version_date[2] < 2009){
		security_message( port: port );
		exit( 0 );
	}
}
else {
	if(http_is_dead( port: port )){
		exit( 0 );
	}
	crapData = crap( length: 60000 );
	url = NASLString( "/", crapData );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

