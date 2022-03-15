if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814778" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_cve_id( "CVE-2019-0801", "CVE-2019-0822", "CVE-2019-0824", "CVE-2019-0825", "CVE-2019-0826", "CVE-2019-0827", "CVE-2019-0828" );
	script_bugtraq_id( 107738, 107699, 107744, 107745, 107746, 107747, 107751 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-10 10:58:49 +0530 (Wed, 10 Apr 2019)" );
	script_name( "Microsoft Office 365 (2016 Click-to-Run) Multiple RCE Vulnerabilities-April19" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Office Click-to-Run updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error when Microsoft Office fails to properly handle certain files.

  - An error when Microsoft Graphics Components fails to handle objects in memory.

  - Multiple errors when the Microsoft Office Access Connectivity Engine improperly
    handles objects in memory.

  - An error when Microsoft Excel because it fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 365 (2016 Click-to-Run)." );
	script_tag( name: "solution", value: "Upgrade to latest version of Microsoft Office
  365 (2016 Click-to-Run) with respect to update channel used. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/office365-proplus-security-updates" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_office_click2run_detect_win.sc" );
	script_mandatory_keys( "MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
officeVer = get_kb_item( "MS/Off/C2R/Ver" );
if(!officeVer || !IsMatchRegexp( officeVer, "^16\\." )){
	exit( 0 );
}
UpdateChannel = get_kb_item( "MS/Office/C2R/UpdateChannel" );
officePath = get_kb_item( "MS/Off/C2R/InstallPath" );
if( UpdateChannel == "Monthly Channel" ){
	if(version_is_less( version: officeVer, test_version: "16.0.11425.20204" )){
		fix = "1903 (Build 11425.20204)";
	}
}
else {
	if( UpdateChannel == "Semi-Annual Channel (Targeted)" ){
		if(version_is_less( version: officeVer, test_version: "16.0.11328.20230" )){
			fix = "1902 (Build 11328.20230)";
		}
	}
	else {
		if(UpdateChannel == "Semi-Annual Channel"){
			if( version_is_less( version: officeVer, test_version: "16.0.9126.2382" ) ){
				fix = "1803 (Build 9126.2382)";
			}
			else {
				if(version_in_range( version: officeVer, test_version: "16.0.10730", test_version2: "16.0.10730.20333" )){
					fix = "1808 (Build 10730.20334)";
				}
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: officeVer, fixed_version: fix, install_path: officePath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

