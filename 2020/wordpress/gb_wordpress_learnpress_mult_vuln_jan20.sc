if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112740" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-05 09:22:00 +0000 (Tue, 05 May 2020)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-11 20:51:00 +0000 (Fri, 11 Jan 2019)" );
	script_cve_id( "CVE-2018-16173", "CVE-2018-16174", "CVE-2018-16175" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress LearnPress Plugin < 3.1.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/learnpress/detected" );
	script_tag( name: "summary", value: "LearnPress plugin for WordPress is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Cross-site scripting (CVE-2018-16173)

  - Open redirect (CVE-2018-16174)

  - SQL injection (CVE-2018-16175)" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to:

  - execute arbitrary scripts on the logged in user's web browser

  - lead a logged in user to be redirected to an arbitrary website by creating a specially crafted URL, which may result in a phishing attack

  - execute arbitrary SQL commands" );
	script_tag( name: "affected", value: "WordPress LearnPress plugin before version 3.1.0." );
	script_tag( name: "solution", value: "Update to version 3.1.0 or later." );
	script_xref( name: "URL", value: "https://jvn.jp/en/jp/JVN85760090/index.html" );
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
if(version_is_less( version: version, test_version: "3.1.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

