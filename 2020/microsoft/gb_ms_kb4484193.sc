if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816870" );
	script_version( "2021-08-11T12:01:46+0000" );
	script_cve_id( "CVE-2019-1463", "CVE-2019-1400" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-16 20:07:00 +0000 (Mon, 16 Dec 2019)" );
	script_tag( name: "creation_date", value: "2020-04-15 13:06:03 +0530 (Wed, 15 Apr 2020)" );
	script_name( "Microsoft Office 2010 Service Pack 2 Multiple Vulnerabilities (KB4484238)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4484238" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors in
  Microsoft Access because it fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability could use a specially crafted file
  to perform actions in the security context of the current user" );
	script_tag( name: "affected", value: "Microsoft Office 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4484238" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer || !IsMatchRegexp( officeVer, "^14\\." )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
	}
}
for key in key_list {
	msPath = registry_get_sz( key: key, item: "CommonFilesDir" );
	if(msPath){
		offPath = msPath + "\\Microsoft Shared\\Office14";
		msdllVer = fetch_file_version( sysPath: offPath, file_name: "acecore.dll" );
		if(msdllVer && version_in_range( version: msdllVer, test_version: "14.0", test_version2: "14.0.7248.4999" )){
			report = report_fixed_ver( file_checked: offPath + "\\acecore.dll", file_version: msdllVer, vulnerable_range: "14.0 - 14.0.7248.4999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

