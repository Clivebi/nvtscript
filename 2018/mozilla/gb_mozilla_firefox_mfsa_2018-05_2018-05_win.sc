CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812750" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2018-5124" );
	script_bugtraq_id( 102843 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-29 13:07:00 +0000 (Mon, 29 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-01-31 11:31:34 +0530 (Wed, 31 Jan 2018)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2018-05_2018-05) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to an arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw exists due to an unsanitized
  browser UI." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code in the
  context of the user running the affected application. Failed exploit attempts
  will likely cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Mozilla Firefox versions before 58.0.1." );
	script_tag( name: "solution", value: "Update to version 58.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-05" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "56", test_version2: "58.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "58.0.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

