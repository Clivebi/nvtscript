if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112697" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-02-17 11:08:00 +0100 (Mon, 17 Feb 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-18 15:26:00 +0000 (Tue, 18 Feb 2020)" );
	script_cve_id( "CVE-2020-8594" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Ninja Forms Plugin < 3.4.23 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/ninja-forms/detected" );
	script_tag( name: "summary", value: "Ninja Forms plugin for WordPress is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to inject malicious content into an affected site." );
	script_tag( name: "affected", value: "WordPress Ninja Forms plugin before version 3.4.23." );
	script_tag( name: "solution", value: "Update to version 3.4.23 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/ninja-forms/#developers" );
	script_xref( name: "URL", value: "https://spider-security.co.uk/blog-cve-cve-2020-8594" );
	exit( 0 );
}
CPE = "cpe:/a:thewpninjas:ninja-forms";
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
if(version_is_less( version: version, test_version: "3.4.23" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.4.23", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

