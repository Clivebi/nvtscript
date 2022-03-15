CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803042" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-11-02 18:49:49 +0530 (Fri, 02 Nov 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress FoxyPress Plugin Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://www.waraxe.us/content-95.html" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51109" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22374" );
	script_tag( name: "summary", value: "This host is running WordPress
  FoxyPress plugin and is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Inputs passed via the

  - 'xtStartDate', 'txtEndDate', and 'txtProductCod' parameters to edit.php,

  - 'id' parameter to foxypress-manage-emails.php,

  - 'status' and 'page' parameters to edit.php and

  - 'url' parameter to foxypress-affiliate.php are not properly sanitised
    before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary web script or HTML in a user's browser session in
  the context of an affected site, manipulate SQL queries by injecting arbitrary SQL
  code and to redirect users to arbitrary web sites and conduct phishing attacks." );
	script_tag( name: "affected", value: "WordPress FoxyPress Plugin Version 0.4.2.5
  and prior." );
	script_tag( name: "solution", value: "No known solution was made available for
  at least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
if(dir == "/"){
	dir = "";
}
url = dir + "/wp-content/plugins/foxypress/dialog.htm";
if(http_vuln_check( port: port, url: url, check_header: TRUE, usecache: TRUE, pattern: ">FoxyPress Plugin<", extra_check: make_list( "/foxypress/forum<",
	 "\"FoxyPressDialog.insert" ) )){
	url = NASLString( dir, "/wp-content/plugins/foxypress/Inventory.csv" );
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "\"Item Code\"", extra_check: make_list( "\"Item Name\",",
		 ",\"Item Category\",",
		 "\"Subscription Start Date\"" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

