CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815876" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_cve_id( "CVE-2019-8835", "CVE-2019-8844", "CVE-2019-8846" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-18 13:19:00 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2019-12-12 11:00:05 +0530 (Thu, 12 Dec 2019)" );
	script_name( "Apple Safari Security Updates (HT210792)" );
	script_tag( name: "summary", value: "This host is installed with Apple Safari
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple memory corruption issues related to improper memory handling.

  - A use after free issue related to improper memory management." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  conduct arbitrary code execution." );
	script_tag( name: "affected", value: "Apple Safari versions before 13.0.4 on macOS." );
	script_tag( name: "solution", value: "Upgrade to Apple Safari 13.0.4 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT210792" );
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
if(version_is_less( version: vers, test_version: "13.0.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "13.0.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

