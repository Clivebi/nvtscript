CPE = "cpe:/a:opencast:opencast";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143446" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-02-04 07:51:44 +0000 (Tue, 04 Feb 2020)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-05 18:51:00 +0000 (Wed, 05 Feb 2020)" );
	script_cve_id( "CVE-2020-5206", "CVE-2020-5222", "CVE-2020-5228", "CVE-2020-5230", "CVE-2020-5231" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenCast < 7.6.0 and 8.0.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_opencast_detect.sc" );
	script_mandatory_keys( "opencast/detected" );
	script_tag( name: "summary", value: "OpenCast is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenCast is prone to multiple vulnerabilities:

  - Authentication Bypass For Endpoints With Anonymous Access (CVE-2020-5206)

  - Hard-Coded Key Used For Remember-me Token (CVE-2020-5222)

  - Unauthenticated Access Via OAI-PMH (CVE-2020-5228)

  - Unsafe Identifiers (CVE-2020-5230)

  - Users with ROLE_COURSE_ADMIN can create new users (CVE-2020-5231)" );
	script_tag( name: "affected", value: "OpenCast versions prior to 7.6.0 and version 8.0.0." );
	script_tag( name: "solution", value: "Update to version 7.6.0, 8.1.0 or later." );
	script_xref( name: "URL", value: "https://github.com/opencast/opencast/security/advisories/GHSA-vmm6-w4cf-7f3x" );
	script_xref( name: "URL", value: "https://github.com/opencast/opencast/security/advisories/GHSA-mh8g-hprg-8363" );
	script_xref( name: "URL", value: "https://github.com/opencast/opencast/security/advisories/GHSA-6f54-3qr9-pjgj" );
	script_xref( name: "URL", value: "https://github.com/opencast/opencast/security/advisories/GHSA-w29m-fjp4-qhmq" );
	script_xref( name: "URL", value: "https://github.com/opencast/opencast/security/advisories/GHSA-94qw-r73x-j7hg" );
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
if(version_is_less( version: version, test_version: "7.6.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.6.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "8.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.1.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

