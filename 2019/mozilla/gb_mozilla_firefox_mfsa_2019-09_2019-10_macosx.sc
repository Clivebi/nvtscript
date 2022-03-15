CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814941" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2019-9810", "CVE-2019-9813" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-13 10:29:00 +0000 (Mon, 13 May 2019)" );
	script_tag( name: "creation_date", value: "2019-03-26 10:56:20 +0530 (Tue, 26 Mar 2019)" );
	script_name( "Mozilla Firefox Security Updates(mfsa_2019-09_2019-10)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - IonMonkey MArraySlice has incorrect alias information and

  - Ionmonkey type confusion with __proto__ mutations." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code and cause denial of service." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 66.0.1 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 66.0.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-09/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
ffVer = infos["version"];
ffPath = infos["location"];
if(version_is_less( version: ffVer, test_version: "66.0.1" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "66.0.1", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

