if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818019" );
	script_version( "2021-08-25T14:01:09+0000" );
	script_cve_id( "CVE-2021-27054", "CVE-2021-27055", "CVE-2021-27056", "CVE-2021-27053", "CVE-2021-27057", "CVE-2021-27058", "CVE-2021-24108" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-16 02:51:00 +0000 (Tue, 16 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-15 12:19:54 +0530 (Mon, 15 Mar 2021)" );
	script_name( "Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities-Mar21" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Office Click-to-Run updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple errors in
  Microsoft Office 365 (2016 Click-to-Run)" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code, gain elevated privileges and disclose sensitive
  information." );
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
	if(version_is_less( version: officeVer, test_version: "16.0.13801.20294" )){
		fix = "2102 (Build 13801.20294)";
	}
}
else {
	if( UpdateChannel == "Semi-Annual Channel (Targeted)" ){
		if(version_is_less( version: officeVer, test_version: "16.0.13801.20294" )){
			fix = "2102 (Build 13801.20294)";
		}
	}
	else {
		if(UpdateChannel == "Semi-Annual Channel"){
			if( version_is_less( version: officeVer, test_version: "16.0.13127.21348" ) ){
				fix = "2008 (Build 13127.21348)";
			}
			else {
				if(version_in_range( version: officeVer, test_version: "16.0.12527", test_version2: "16.0.12527.21686" )){
					fix = "2002 (Build 12527.21686)";
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

