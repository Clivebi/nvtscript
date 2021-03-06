if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814755" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-0540", "CVE-2019-0582", "CVE-2019-0669", "CVE-2019-0671", "CVE-2019-0672", "CVE-2019-0673", "CVE-2019-0674" );
	script_bugtraq_id( 106863, 106433, 106897, 106928, 106929, 106930, 106931 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-14 12:17:57 +0530 (Thu, 14 Feb 2019)" );
	script_name( "Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities-February19" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Office Click-to-Run updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error when Microsoft Office does not validate URLs.

  - An error when the Windows Jet Database Engine improperly handles objects in
    memory.

  - An error when Microsoft Excel improperly discloses the contents of its memory.

  - Multiple errors when the Microsoft Office Access Connectivity Engine improperly
    handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user, bypass security
  restriction and gain access to sensitive information." );
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
	if(version_is_less( version: officeVer, test_version: "16.0.11231.20174" )){
		fix = "1901 (Build 11231.20174)";
	}
}
else {
	if( UpdateChannel == "Semi-Annual Channel (Targeted)" ){
		if(version_is_less( version: officeVer, test_version: "16.0.10730.20280" )){
			fix = "1808 (Build 10730.20280)";
		}
	}
	else {
		if(UpdateChannel == "Semi-Annual Channel"){
			if( version_is_less( version: officeVer, test_version: "16.0.8431.2372" ) ){
				fix = "1708 (Build 8431.2372)";
			}
			else {
				if( version_in_range( version: officeVer, test_version: "16.0.9000", test_version2: "16.0.9126.2355" ) ){
					fix = "1803 (Build 9126.2356)";
				}
				else {
					if(version_in_range( version: officeVer, test_version: "16.0.10730", test_version2: "16.0.10730.20279" )){
						fix = "1808 (Build 10730.20280)";
					}
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

