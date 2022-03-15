if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112029" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-25 10:34:31 +0200 (Fri, 25 Aug 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-08 16:24:00 +0000 (Mon, 08 Jul 2019)" );
	script_cve_id( "CVE-2017-12977" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Photo Gallery Plugin SQL Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/photo-gallery/detected" );
	script_tag( name: "summary", value: "WordPress plugin Photo Gallery by Web-Dorado has a SQL injection vulnerability related to bwg_edit_tag() in photo-gallery.php and edit_tag() in admin/controllers/BWGControllerTags_bwg.php. It is exploitable by administrators via the tag_id parameter." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Web-Dorado 'Photo Gallery by WD - Responsive Photo Gallery' plugin before 1.3.51." );
	script_tag( name: "solution", value: "Update to version 1.3.51 or later." );
	script_xref( name: "URL", value: "https://github.com/jgj212/Advisories/blob/master/photo-gallery.1.3.50-SQL" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/photo-gallery/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:10web:photo-gallery";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.3.51" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.51", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

