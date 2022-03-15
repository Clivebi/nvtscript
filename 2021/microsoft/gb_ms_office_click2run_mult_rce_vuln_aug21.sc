if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818181" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-36941", "CVE-2021-34478" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-20 19:00:00 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 17:35:18 +0530 (Wed, 11 Aug 2021)" );
	script_name( "Microsoft Office 365 (2016 Click-to-Run) Multiple RCE Vulnerabilities - Aug21" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Office Click-to-Run updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple errors in
  Microsoft Office 365 (2016 Click-to-Run)" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to remotely execute code on an affected system." );
	script_tag( name: "affected", value: "Microsoft Office 365 (2016 Click-to-Run)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
	if(version_is_less( version: officeVer, test_version: "16.0.14228.20250" )){
		fix = "2107 (Build 14228.20250)";
	}
}
else {
	if( UpdateChannel == "Semi-Annual Channel (Targeted)" ){
		if(version_is_less( version: officeVer, test_version: "16.0.13801.20864" )){
			fix = "2102 (Build 13801.20864)";
		}
	}
	else {
		if(UpdateChannel == "Semi-Annual Channel"){
			if( version_is_less( version: officeVer, test_version: "16.0.13127.21736" ) ){
				fix = "2008 (Build 13127.21736)";
			}
			else {
				if(version_in_range( version: officeVer, test_version: "16.0.12527", test_version2: "16.0.12527.22016" )){
					fix = "2002 (Build 12527.22017)";
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

