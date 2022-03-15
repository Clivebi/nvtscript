CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808036" );
	script_version( "2019-11-12T13:33:43+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-11-12 13:33:43 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "creation_date", value: "2016-05-17 11:58:45 +0530 (Tue, 17 May 2016)" );
	script_name( "WordPress Core Reflected XSS Vulnerability May16 (Windows)" );
	script_tag( name: "summary", value: "This host is running WordPress and is prone
  to reflected xss vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  MediaElement.js library used for media players." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attacker to execute arbitrary script code in a user's browser
  session within the trust relationship." );
	script_tag( name: "affected", value: "WordPress versions 4.2.x through 4.5.1 on
  Windows." );
	script_tag( name: "solution", value: "Update to WordPress version 4.5.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://wordpress.org/news/2016/05/wordpress-4-5-2" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_in_range( version: wpVer, test_version: "4.2", test_version2: "4.5.1" )){
	report = report_fixed_ver( installed_version: wpVer, fixed_version: "4.5.2" );
	security_message( data: report, port: wpPort );
	exit( 0 );
}

