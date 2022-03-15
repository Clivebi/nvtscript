if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811663" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2017-8676", "CVE-2017-8682", "CVE-2017-8695" );
	script_bugtraq_id( 100755, 100772, 100773 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-10 19:58:00 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2017-09-13 11:42:17 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft Office 2010 Service Pack 2 Multiple Vulnerabilities (KB3213638)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB3213638" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The way that the Windows Graphics Device Interface (GDI) handles objects in
  memory, allowing an attacker to retrieve information from a targeted system.

  - The Windows font library improperly handles specially crafted embedded
  fonts.

  - Windows Uniscribe improperly discloses the contents of its memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to retrieve information from a targeted system. By itself, the information
  disclosure does not allow arbitrary code execution. However, it could allow
  arbitrary code to be run if the attacker uses it in combination with another
  vulnerability." );
	script_tag( name: "affected", value: "Microsoft Office 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3213638" );
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
OfficeVer = get_kb_item( "MS/Office/Ver" );
if(!OfficeVer || !IsMatchRegexp( OfficeVer, "^(14\\.)" )){
	exit( 0 );
}
msPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
if(msPath){
	offPath = msPath + "\\Microsoft Shared\\OFFICE14";
	msdllVer = fetch_file_version( sysPath: offPath, file_name: "Ogl.dll" );
	if(!msdllVer){
		exit( 0 );
	}
	if(IsMatchRegexp( msdllVer, "^(14\\.)" ) && version_is_less( version: msdllVer, test_version: "14.0.7188.5000" )){
		report = "File checked:     " + offPath + "\\Ogl.dll" + "\n" + "File version:     " + msdllVer + "\n" + "Vulnerable range: " + "14.0 - 14.0.7188.4999" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

