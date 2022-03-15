if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112737" );
	script_version( "2021-08-09T02:00:54+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 02:00:54 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-05 09:22:00 +0000 (Tue, 05 May 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-06 17:25:00 +0000 (Fri, 06 Aug 2021)" );
	script_cve_id( "CVE-2020-6010", "CVE-2020-11510", "CVE-2020-11511" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress LearnPress Plugin < 3.2.6.9 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/learnpress/detected" );
	script_tag( name: "summary", value: "LearnPress plugin for WordPress is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - SQL injection (CVE-2020-6010)

  - Authenticated page creation and status modification (CVE-2020-11510)

  - Privilege escalation (CVE-2020-11511)" );
	script_tag( name: "affected", value: "WordPress LearnPress plugin before version 3.2.6.9." );
	script_tag( name: "solution", value: "Update to version 3.2.6.9 or later." );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2020/04/high-severity-vulnerabilities-patched-in-learnpress/" );
	script_xref( name: "URL", value: "https://research.checkpoint.com/2020/e-learning-platforms-getting-schooled-multiple-vulnerabilities-in-wordpress-most-popular-learning-management-system-plugins/" );
	exit( 0 );
}
CPE = "cpe:/a:thimpress:learnpress";
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
if(version_is_less( version: version, test_version: "3.2.6.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.6.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

