if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814252" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-8502", "CVE-2018-8501", "CVE-2018-8504", "CVE-2018-8432" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-10-10 11:39:37 +0530 (Wed, 10 Oct 2018)" );
	script_name( "Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities-October18" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Office Click-to-Run updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Errors in Microsoft Excel, Microsoft PowerPoint and Microsoft Word
    when the software fails to properly handle objects in Protected View.

  - Missing update for Microsoft Office that provides enhanced security as a
    defense-in-depth measure.

  - An error in the way that Microsoft Graphics Components handle objects in
    memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 365 (2016 Click-to-Run)." );
	script_tag( name: "solution", value: "Upgrade to latest version of Microsoft Office
  365 (2016 Click-to-Run) with respect to update channel used. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8502" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV180026" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8501" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8504" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8432" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-gb/officeupdates/release-notes-office365-proplus" );
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
	if(version_is_less( version: officeVer, test_version: "16.0.10827.20150" )){
		fix = "1809 (Build 10827.20150)";
	}
}
else {
	if( UpdateChannel == "Semi-Annual Channel (Targeted)" ){
		if(version_is_less( version: officeVer, test_version: "16.0.10730.20155" )){
			fix = "1808 (Build 10730.20155)";
		}
	}
	else {
		if(UpdateChannel == "Semi-Annual Channel"){
			if( version_is_less( version: officeVer, test_version: "16.0.8431.2316" ) ){
				fix = "Version 1708 (Build 8431.2316)";
			}
			else {
				if(version_in_range( version: officeVer, test_version: "16.0.9000", test_version2: "16.0.9126.2294" )){
					fix = "1803 (Build 9126.2295)";
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

