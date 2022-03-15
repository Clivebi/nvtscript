if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814972" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_cve_id( "CVE-2019-0946", "CVE-2019-0947", "CVE-2019-0945" );
	script_bugtraq_id( 108193, 108192, 108194 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-17 18:16:00 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-15 12:25:43 +0530 (Wed, 15 May 2019)" );
	script_name( "Microsoft Office 2010 Service Pack 2 Multiple Vulnerabilities (KB4464567)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4464567" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist when the Microsoft
  Office Access Connectivity Engine improperly handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to elevate privileges and execute arbitrary code in the context of the currently
  logged-in user. Failed exploit attempts will likely result in denial of service
  conditions." );
	script_tag( name: "affected", value: "Microsoft Office 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4464567/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(!os_arch = get_kb_item( "SMB/Windows/Arch" )){
	exit( 0 );
}
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
		if(msdllVer && version_in_range( version: msdllVer, test_version: "14.0", test_version2: "14.0.7232.4999" )){
			report = report_fixed_ver( file_checked: offPath + "\\acecore.dll", file_version: msdllVer, vulnerable_range: "14.0 - 14.0.7232.4999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

