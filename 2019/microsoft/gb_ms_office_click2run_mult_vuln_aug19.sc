if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815196" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-1199", "CVE-2019-1204", "CVE-2019-1200", "CVE-2019-1205", "CVE-2019-1201", "CVE-2019-1155" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-14 11:52:30 +0530 (Wed, 14 Aug 2019)" );
	script_name( "Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities-Aug19" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Office Click-to-Run updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple errors in Microsoft Outlook when the software fails to properly handle
    objects in memory.

  - An error when Microsoft Outlook initiates processing of incoming messages
    without sufficient validation of the formatting of the messages.

  - Multiple errors in Microsoft Word software when it fails to properly handle objects
    in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to arbitrary code in the context of the current user, force Outlook to load a
  local or remote message store and perform actions in the security context of the
  current user" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "affected", value: "Microsoft Office 365 (2016 Click-to-Run)." );
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
	if(version_is_less( version: officeVer, test_version: "16.0.11901.20218" )){
		fix = "1907 (Build 11901.20218)";
	}
}
else {
	if( UpdateChannel == "Semi-Annual Channel (Targeted)" ){
		if(version_is_less( version: officeVer, test_version: "16.0.11328.20392" )){
			fix = "1902 (Build 11328.20392)";
		}
	}
	else {
		if(UpdateChannel == "Semi-Annual Channel"){
			if( version_is_less( version: officeVer, test_version: "16.0.9126.2432" ) ){
				fix = "1803 (Build 9126.2432)";
			}
			else {
				if( version_in_range( version: officeVer, test_version: "16.0.10730", test_version2: "16.0.10730.20369" ) ){
					fix = "1808 (Build 10730.20370)";
				}
				else {
					if(version_in_range( version: officeVer, test_version: "16.0.11328", test_version2: "16.0.11328.20391" )){
						fix = "1902 (Build 11328.20392)";
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

