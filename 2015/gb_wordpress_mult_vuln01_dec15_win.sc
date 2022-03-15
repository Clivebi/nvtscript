CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806800" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-5734", "CVE-2015-5733", "CVE-2015-5732", "CVE-2015-5731", "CVE-2015-5730", "CVE-2015-2213" );
	script_bugtraq_id( 76331, 76160 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-12-15 13:15:38 +0530 (Tue, 15 Dec 2015)" );
	script_name( "WordPress Multiple Vulnerabilities-01 Dec15 (Windows)" );
	script_tag( name: "summary", value: "This host is running WordPress and is prone
  to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the legacy theme preview implementation within the  file
   'wp-includes/theme.php', which is not properly handling the user input.

  - An error in the function 'refreshAdvancedAccessibilityOfItem' within file
    'wp-admin/js/nav-menu.js', which is not properly handling the user input.

  - An error in the function 'WP_Nav_Menu_Widget' class within file
   'wp-includes/default-widgets.php', which is not properly handling the user
    input.

  - Function 'wp_untrash_post_comments' is not properly handling a comment after
    retrieving from trash within the file 'wp-includes/post.php'

  - No usage of constant time comaprision for widgets in function
    'sanitize_widget_instance' leads to timing side-channel attack by measuring
    the delay before inequality is calculated which is
    within the file 'wp-includes/class-wp-customize-widgets.php'

  - Cross-site request forgery (CSRF) vulnerability in 'wp-admin/post.php'" );
	script_tag( name: "impact", value: "Successfully exploiting will allow
  remote attackers to inject arbitrary web script code in a user's browser
  session within the trust relationship between their browser and the server,
  to inject or manipulate SQL queries in the back-end database and to cause
  denial of service." );
	script_tag( name: "affected", value: "WordPress Versions before 4.2.4
  on Windows." );
	script_tag( name: "solution", value: "Update to WordPress 4.2.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2015/q3/290" );
	script_xref( name: "URL", value: "https://wordpress.org/news/2015/08/wordpress-4-2-4-security-and-maintenance-release/" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "os_detection.sc", "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!wpVer = get_app_version( cpe: CPE, port: wpPort )){
	exit( 0 );
}
if(version_is_less( version: wpVer, test_version: "4.2.4" )){
	report = "Installed Version: " + wpVer + "\n" + "Fixed Version: 4.2.4" + "\n";
	security_message( port: wpPort, data: report );
	exit( 0 );
}

