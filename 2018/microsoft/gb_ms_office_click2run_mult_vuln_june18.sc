if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813431" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-8246", "CVE-2018-8248", "CVE-2018-8244" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-06-13 11:02:56 +0530 (Wed, 13 Jun 2018)" );
	script_name( "Microsoft Office 2016 Click-to-Run (C2R) Multiple Vulnerabilities-June18" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Office Click-to-Run updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple errors in Microsoft Excel because it fails to properly handle objects in memory.

  - An error in Microsoft Excel which improperly discloses the contents of its
    memory.

  - An error in the Microsoft Outlook when Microsoft Outlook does not validate
    attachment headers properly" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user, gain access to
  potentially sensitive information and gain elevated privileges." );
	script_tag( name: "affected", value: "Microsoft Office 2016 Click-to-Run." );
	script_tag( name: "solution", value: "Upgrade to latest version of Microsoft Office
  2016 Click-to-Run with respect to update channel used. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/office/mt465751" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(version_is_less( version: officeVer, test_version: "16.0.9330.2118" )){
		fix = "1805 (Build 9330.2118)";
	}
}
else {
	if( UpdateChannel == "Semi-Annual Channel" ){
		if(version_is_less( version: officeVer, test_version: "16.0.8431.2270" )){
			fix = "1708 (Build 8431.2270)";
		}
	}
	else {
		if( UpdateChannel == "Semi-Annual Channel (Targeted)" ){
			if(version_is_less( version: officeVer, test_version: "16.0.9126.2227" )){
				fix = "1803 (Build 9126.2227)";
			}
		}
		else {
			if(UpdateChannel == "Deferred Channel"){
				if(version_is_less( version: officeVer, test_version: "16.0.8201.2294" )){
					fix = "1705 (Build 8201.2294)";
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

