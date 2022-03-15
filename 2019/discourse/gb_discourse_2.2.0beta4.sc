CPE = "cpe:/a:discourse:discourse";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141936" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-29 13:51:11 +0700 (Tue, 29 Jan 2019)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:36:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2018-16468" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Discourse < 2.2.0.beta4 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_discourse_detect.sc" );
	script_mandatory_keys( "discourse/detected" );
	script_tag( name: "summary", value: "Discourse is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "Discourse before version 2.2.0.beta4." );
	script_tag( name: "solution", value: "Update to version 2.2.0.beta4." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://meta.discourse.org/t/discourse-2-2-0-beta4-release-notes/101272" );
	script_xref( name: "URL", value: "https://github.com/discourse/discourse/commit/57ab6bcba13ee3a2c4d5acc1eb950479c9e48e17" );
	script_xref( name: "URL", value: "https://github.com/discourse/discourse/commit/a84b6b6b0c3dbb4e3b3e4325e4b7bc0942f9f3de" );
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
vers = infos["version"];
if(version_is_less( version: vers, test_version: "2.2.0" ) || version_in_range( version: vers, test_version: "2.2.0.beta1", test_version2: "2.2.0.beta3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.2.0.beta4", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

