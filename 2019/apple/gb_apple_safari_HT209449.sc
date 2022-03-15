CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814820" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2019-6228", "CVE-2019-6215", "CVE-2019-6212", "CVE-2019-6216", "CVE-2019-6217", "CVE-2019-6226", "CVE-2019-6227", "CVE-2019-6233", "CVE-2019-6234", "CVE-2019-6229" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-23 12:46:20 +0530 (Wed, 23 Jan 2019)" );
	script_name( "Apple Safari Security Update (HT209449) - Mac OS X" );
	script_tag( name: "summary", value: "Apple Safari is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A cross-site scripting issue.

  - A type confusion issue, multiple memory corruption issues exist in
    memory handling.

  - A logic issue exists in input validation." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code and conduct cross site scripting by
  processing maliciously crafted web content." );
	script_tag( name: "affected", value: "Apple Safari versions before 12.0.3." );
	script_tag( name: "solution", value: "Update to version 12.0.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT209449" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "12.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.0.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

