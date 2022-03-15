CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813393" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2018-6126" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-15 21:50:00 +0000 (Tue, 15 Jan 2019)" );
	script_tag( name: "creation_date", value: "2018-06-07 10:53:51 +0530 (Thu, 07 Jun 2018)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2018-14_2018-14) - Mac OS X" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw exists due to a heap buffer
  overflow can occur in the Skia library when rasterizing paths using a
  maliciously crafted SVG file with anti-aliasing turned off." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to result in a potentially
  exploitable crash." );
	script_tag( name: "affected", value: "Mozilla Firefox versions before 60.0.2." );
	script_tag( name: "solution", value: "Update to version 60.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-14/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "60.0.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "60.0.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

