CPE = "cpe:/a:open-emr:openemr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142700" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-06 09:13:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-14529", "CVE-2019-14530", "CVE-2019-3963", "CVE-2019-3964", "CVE-2019-3965", "CVE-2019-3966", "CVE-2019-3967", "CVE-2019-3968", "CVE-2019-8368", "CVE-2019-8371" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenEMR < 5.0.2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openemr_detect.sc" );
	script_mandatory_keys( "openemr/installed" );
	script_tag( name: "summary", value: "OpenEMR is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "OpenEMR is prone to multiple vulnerabilities:

  - SQL injection vulnerability in interface/forms/eye_mag/save.php (CVE-2019-14529)

  - Authenticated file download vulnerability (CVE-2019-14530)

  - Multiple XSS vulnerabilities (CVE-2019-3963, CVE-2019-3964, CVE-2019-3965, CVE-2019-3966, CVE-2019-8368)

  - Directory Traversal and Arbitrary File Download vulnerability (CVE-2019-3967)

  - Multiple command injection vulnerabilities (CVE-2019-3968, CVE-2019-8371)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "OpenEMR versions prior to 5.0.2." );
	script_tag( name: "solution", value: "Update to version 5.0.2 or later." );
	script_xref( name: "URL", value: "https://github.com/openemr/openemr/pull/2592" );
	script_xref( name: "URL", value: "https://github.com/Wezery/CVE-2019-14530" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/research/tra-2019-40" );
	script_xref( name: "URL", value: "https://know.bishopfox.com/advisories/openemr-5-0-16-remote-code-execution-cross-site-scripting" );
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
if(version_is_less( version: version, test_version: "5.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

