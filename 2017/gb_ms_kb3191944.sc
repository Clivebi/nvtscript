if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811098" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-8509", "CVE-2017-8511", "CVE-2017-8512" );
	script_bugtraq_id( 98812, 98815, 98816 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 14:05:00 +0530 (Wed, 14 Jun 2017)" );
	script_name( "Microsoft Office Multiple Vulnerabilities (KB3191944)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3191944" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors
  in the Microsoft Office software when the Office software fails to properly
  handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow the
  remote attacker to execute arbitrary code in the context of current user." );
	script_tag( name: "affected", value: "Microsoft Office 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3191944" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!officeVer || !IsMatchRegexp( officeVer, "^16\\." )){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!path){
	exit( 0 );
}
offPath = path + "\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX86\\Microsoft Shared\\Office16";
offdllVer = fetch_file_version( sysPath: offPath, file_name: "mso.dll" );
if(!offdllVer){
	exit( 0 );
}
if(IsMatchRegexp( offdllVer, "^16\\." ) && version_is_less( version: offdllVer, test_version: "16.0.4549.1001" )){
	report = "File checked:     " + offPath + "\\Mso.dll" + "\n" + "File version:     " + offdllVer + "\n" + "Vulnerable range: " + "16.0 - 16.0.4549.1000" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

