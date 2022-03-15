CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815550" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_cve_id( "CVE-2019-8848", "CVE-2019-15903", "CVE-2019-8835", "CVE-2019-8844", "CVE-2019-8846" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-18 13:19:00 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2019-12-17 11:44:08 +0530 (Tue, 17 Dec 2019)" );
	script_name( "Apple iTunes Security Updates (HT210793)" );
	script_tag( name: "summary", value: "This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - A use after free issue in WebKit.

  - Multiple memory corruption issues." );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers
  to gain elevated privileges, execute arbitrary code or gain access to sensitive
  information." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.10.3 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Apple iTunes 12.10.3 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT210793" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "12.10.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.10.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

