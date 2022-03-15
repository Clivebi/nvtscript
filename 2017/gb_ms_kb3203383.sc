if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811212" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2017-8510" );
	script_bugtraq_id( 98813 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-21 15:13:34 +0530 (Wed, 21 Jun 2017)" );
	script_name( "Microsoft Office Remote Code Execution Vulnerability (KB3203383)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3178667" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in Microsoft
  Office software when the Office software fails to properly handle objects in
  memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to use a specially crafted file and perform actions in the security context of
  the current user. The file could then, for example, take actions on behalf of
  the logged-on user with the same permissions as the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3203383" );
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
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer || !IsMatchRegexp( officeVer, "^16\\." )){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!path){
	exit( 0 );
}
offPath = path + "\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX86\\Microsoft Shared\\GRPHFLT";
offdllVer = fetch_file_version( sysPath: offPath, file_name: "epsimp32.flt" );
if(!offdllVer){
	exit( 0 );
}
if(IsMatchRegexp( offdllVer, "^2012\\.1600\\." ) && version_is_less( version: offdllVer, test_version: "2012.1600.8201.1003" )){
	report = "File checked:     " + offPath + "\\epsimp32.flt" + "\n" + "File version:     " + offdllVer + "\n" + "Vulnerable range: " + "2012.1600.0.0 - 2012.1600.8201.1002" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );
