CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818555" );
	script_version( "2021-09-24T05:06:20+0000" );
	script_cve_id( "CVE-2021-30835", "CVE-2021-30847", "CVE-2021-30849" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-24 05:06:20 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-22 17:41:46 +0530 (Wed, 22 Sep 2021)" );
	script_name( "Apple iTunes Security Update(HT212817)" );
	script_tag( name: "summary", value: "The host is missing an important security
  update according to Apple." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to,

  - Multiple memory corruption issues.

  - An input validation error." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  conduct arbitrary code execution." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.12." );
	script_tag( name: "solution", value: "Upgrade to Apple iTunes 12.12 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT212817" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_itunes_detection_win_900123.sc" );
	script_mandatory_keys( "iTunes/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "12.12" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.12", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

