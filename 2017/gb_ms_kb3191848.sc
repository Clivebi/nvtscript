if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811094" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2017-8528", "CVE-2017-0282", "CVE-2017-0284", "CVE-2017-0285", "CVE-2017-8534" );
	script_bugtraq_id( 98949, 98885, 98918, 98914, 98822 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-26 15:04:00 +0000 (Mon, 26 Jun 2017)" );
	script_tag( name: "creation_date", value: "2017-06-14 11:49:43 +0530 (Wed, 14 Jun 2017)" );
	script_name( "Microsoft Office Multiple Vulnerabilities (KB3191848)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB3191848" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple errors in Windows Uniscribe which improperly discloses the contents
    of its memory.

  - An error due to the way Windows Uniscribe handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain sensitive information and take complete control of the
  affected system. An attacker could then install programs. View, change, or
  delete data, or create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft Office 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3191848" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
offVer = get_kb_item( "MS/Office/Ver" );
if(!offVer || !IsMatchRegexp( offVer, "^14\\." )){
	exit( 0 );
}
msPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
if(msPath){
	offPath = msPath + "\\Microsoft Shared\\OFFICE14";
	msdllVer = fetch_file_version( sysPath: offPath, file_name: "Ogl.dll" );
	if(!msdllVer){
		exit( 0 );
	}
	if(IsMatchRegexp( msdllVer, "^14\\.0" ) && version_is_less( version: msdllVer, test_version: "14.0.7182.5000" )){
		report = "File checked:     " + offPath + "\\Ogl.dll" + "\n" + "File version:     " + msdllVer + "\n" + "Vulnerable range: " + "14.0 - 14.0.7182.4999" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

