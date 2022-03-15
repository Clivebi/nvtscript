CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816741" );
	script_version( "2021-09-09T12:46:11+0000" );
	script_cve_id( "CVE-2020-6821", "CVE-2020-6822", "CVE-2020-6823", "CVE-2020-6824", "CVE-2020-6825", "CVE-2020-6826" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 12:46:11 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-01 13:38:00 +0000 (Fri, 01 May 2020)" );
	script_tag( name: "creation_date", value: "2020-04-08 13:17:30 +0530 (Wed, 08 Apr 2020)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2020-12_2020-13) - Mac OS X" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A file overwrite issue in the user's profile directory.

  - An uninitialized memory could be read when using the WebGL copyTexSubImage
    method.

  - An out of bounds write issue in GMPDecodeData when processing large images.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation allows remote
  attackers to execute arbitrary code and disclose sensitive data." );
	script_tag( name: "affected", value: "Mozilla Firefox versions before 75." );
	script_tag( name: "solution", value: "Update to version 75 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2020-12/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "75" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "75", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

