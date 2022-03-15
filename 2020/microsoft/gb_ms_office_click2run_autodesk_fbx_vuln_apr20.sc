if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816893" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_cve_id( "CVE-2020-7080", "CVE-2020-7081", "CVE-2020-7082", "CVE-2020-7083", "CVE-2020-7084", "CVE-2020-7085" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-21 17:28:00 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-23 12:01:55 +0530 (Thu, 23 Apr 2020)" );
	script_name( "Microsoft Office 365 (2016 Click-to-Run) Autodesk FBX Vulnerabilities-Apr20" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Office Click-to-Run updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A buffer overflow error in FBX's SDK.

  - A type confusion error in FBX's SDK.

  - A use-after-free error in FBX's SDK.

  - An integer overflow error in FBX's SDK.

  - A null pointer dereference error in FBX's SDK

  - The heap overflow error in FBX parser." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code and conduct a denial-of-service condition on the
  affected system." );
	script_tag( name: "affected", value: "Microsoft Office 365 (2016 Click-to-Run)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/office365-proplus-security-updates" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(UpdateChannel == "Monthly Channel"){
	if(version_is_less( version: officeVer, test_version: "16.0.12624.20466" )){
		report = report_fixed_ver( installed_version: officeVer, fixed_version: "2003 (Build 12624.20466)", install_path: officePath );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

