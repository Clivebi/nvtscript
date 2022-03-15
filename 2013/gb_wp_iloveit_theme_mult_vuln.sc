CPE = "cpe:/a:cosmothemes:iloveit";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803844" );
	script_version( "2020-09-10T09:13:09+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-09-10 09:13:09 +0000 (Thu, 10 Sep 2020)" );
	script_tag( name: "creation_date", value: "2013-07-29 12:46:47 +0530 (Mon, 29 Jul 2013)" );
	script_name( "WordPress I Love It Theme Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_theme_http_detect.sc" );
	script_mandatory_keys( "wordpress/theme/iloveit/detected" );
	script_tag( name: "summary", value: "The WordPress theme 'I Love It' is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a HTTP GET request and checks whether it is able to disclose the path or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Input passed via 'playerID' parameter to '/iloveit/lib/php/assets/player.swf'
  is not properly sanitised before being return to the user.

  - No proper access restriction to certain files." );
	script_tag( name: "affected", value: "WordPress I Love It Theme version 1.9 and prior." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to execute arbitrary HTML
or script code in the context of the affected site and disclose some sensitive
information." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013070104" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122386/wpiloveit-xssdisclose.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-i-love-it-xss-content-spoofing-path-disclosure" );
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
url = dir + "/index.php";
if(http_vuln_check( port: port, url: url, pattern: "<b>Fatal error</b>: .*index.php" )){
	security_message( port );
	exit( 0 );
}
exit( 0 );

