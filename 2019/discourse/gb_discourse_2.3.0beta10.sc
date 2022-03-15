CPE = "cpe:/a:discourse:discourse";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108602" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_cve_id( "CVE-2018-3721", "CVE-2018-16487" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-17 06:03:35 +0000 (Mon, 17 Jun 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-18 16:38:00 +0000 (Fri, 18 Sep 2020)" );
	script_name( "Discourse < 2.3.0.beta10 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_discourse_detect.sc" );
	script_mandatory_keys( "discourse/detected" );
	script_tag( name: "summary", value: "Discourse is prone to multiple vulnerabilities including vulnerabilities
  in 3rdparty components." );
	script_tag( name: "insight", value: "The following security relevant fixes/updates where done:

  - Lodash 4.17.11

  - Updates lodash from 1.3.0 to 4.17.5

  - Avoid use of send in favor of public_send

  - Fix tab nabbing." );
	script_tag( name: "affected", value: "Discourse before version 2.3.0.beta10." );
	script_tag( name: "solution", value: "Update to version 2.3.0.beta10." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://meta.discourse.org/t/discourse-2-3-0-beta10-release-notes/119054" );
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
if(version_is_less( version: vers, test_version: "2.3.0" ) || version_in_range( version: vers, test_version: "2.3.0.beta1", test_version2: "2.3.0.beta9" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.0.beta10", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

