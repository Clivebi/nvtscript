CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805946" );
	script_version( "2019-11-12T13:33:43+0000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-11-12 13:33:43 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "creation_date", value: "2015-08-07 11:29:02 +0530 (Fri, 07 Aug 2015)" );
	script_name( "WordPress 'admin impersonation via comments' CSRF Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is running WordPress and is prone
  to cross-site request forgery vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The error exists as the application does not
  require a nonce value when posting comments." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to impersonate the admin via comments." );
	script_tag( name: "affected", value: "WordPress versions 3.8.1, 3.8.2 and 4.2.2
  on Windows." );
	script_tag( name: "solution", value: "Update to WordPress version 4.3.1
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Aug/10" );
	script_xref( name: "URL", value: "https://security.dxw.com/advisories/comment-form-csrf-allows-admin-impersonation-via-comments-in-wordpress-4-2-2/" );
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
if(version_is_equal( version: wpVer, test_version: "4.2.2" ) || version_is_equal( version: wpVer, test_version: "3.8.2" ) || version_is_equal( version: wpVer, test_version: "3.8.1" )){
	report = "Installed Version: " + wpVer + "\n" + "Fixed Version:      4.3.1\n";
	security_message( data: report, port: wpPort );
	exit( 0 );
}

