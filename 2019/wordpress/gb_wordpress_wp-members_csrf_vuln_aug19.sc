if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113518" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-16 11:20:02 +0000 (Mon, 16 Sep 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-28 19:56:00 +0000 (Wed, 28 Aug 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-15660" );
	script_name( "WordPress WP-Members Membership Plugin < 3.2.8 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-members/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WP-Members Membership is prone to
  a cross-site request forgery (CSRF) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  perform action in the context of another user." );
	script_tag( name: "affected", value: "WordPress WP-Members Membership plugin through version 3.2.7." );
	script_tag( name: "solution", value: "Update to version 3.2.8 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-members/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:chad_butler:wp-members";
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
if(version_is_less( version: version, test_version: "3.2.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.8", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );
