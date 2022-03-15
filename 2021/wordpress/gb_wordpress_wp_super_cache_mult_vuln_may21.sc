CPE = "cpe:/a:automattic:wp_super_cache";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146160" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-22 04:25:59 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 19:48:00 +0000 (Fri, 11 Jun 2021)" );
	script_cve_id( "CVE-2021-24312", "CVE-2021-24329" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WP Super Cache Plugin < 1.7.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-super-cache/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WP Super Cache is prone to multiple
  vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-24312: Authenticated stored cross-site scripting (XSS)

  - CVE-2021-24329: Authenticated remote code execution (RCE)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress WP Super Cache plugin through version 1.7.2." );
	script_tag( name: "solution", value: "Update to version 1.7.3 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-super-cache/#developers" );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/9df86d05-1408-4c22-af55-5e3d44249fd0" );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/2142c3d3-9a7f-4e3c-8776-d469a355d62f" );
	exit( 0 );
}
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
if(version_is_less( version: version, test_version: "1.7.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

