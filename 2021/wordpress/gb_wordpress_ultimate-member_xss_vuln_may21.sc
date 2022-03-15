CPE = "cpe:/a:ultimatemember:ultimate-member";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146188" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-29 08:14:49 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-03 17:09:00 +0000 (Thu, 03 Jun 2021)" );
	script_cve_id( "CVE-2021-24306" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Ultimate Member Plugin < 2.1.20 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/ultimate-member/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Ultimate Member is prone to a cross-site
  scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Ultimate Member Member plugin does not properly sanitise,
  validate or encode the query string when generating a link to edit user's own profile, leading to
  an authenticated reflected XSS issue. Knowledge of the targeted username is required to exploit
  this, and attackers would then need to make the related logged in user open a malicious link." );
	script_tag( name: "affected", value: "WordPress Ultimate Member plugin version 2.1.19 and prior." );
	script_tag( name: "solution", value: "Update to version 2.1.20 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/ultimate-member/#developers" );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/35516555-c50c-486a-886c-df49c9e51e2c" );
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
if(version_is_less( version: version, test_version: "2.1.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.20", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

