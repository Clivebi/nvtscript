CPE = "cpe:/a:discourse:discourse";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108612" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-07-17 11:26:10 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 19:15:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2019-1020017", "CVE-2019-1020018" );
	script_name( "Discourse < 2.4.0.beta2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_discourse_detect.sc" );
	script_mandatory_keys( "discourse/detected" );
	script_tag( name: "summary", value: "Discourse is prone to multiple vulnerabilities including XSS and
  SQL injection flaws." );
	script_tag( name: "insight", value: "The following flaws exist / The following security fixes are included:

  - XSS when displaying watched words in admin panel

  - SQL injection with default categories

  - Upgrade lodash

  - XSS with title selector on preferences page

  - Strip HTML from invite emails

  - XSS in routes

  - Escape email text for posts containing [details].

  - lacks a confirmation screen when logging in via an email link (CVE-2019-1020018).

  - lacks a confirmation screen when logging in via a user-api OTP (CVE-2019-1020017)." );
	script_tag( name: "affected", value: "Discourse before version 2.4.0.beta2." );
	script_tag( name: "solution", value: "Update to version 2.4.0.beta2." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://meta.discourse.org/t/discourse-2-4-0-beta2-release-notes/122978" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "2.4.0" ) || version_is_equal( version: vers, test_version: "2.4.0.beta1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.0.beta2", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

