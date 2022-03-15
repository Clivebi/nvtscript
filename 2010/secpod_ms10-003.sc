if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900228" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0243" );
	script_name( "Microsoft Office (MSO) Remote Code Execution Vulnerability (978214)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/977896" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0336" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-003" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc", "smb_reg_service_pack.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Microsoft Office XP 3 and prior." );
	script_tag( name: "insight", value: "An unspecified issue exists in Mso.dll while handling specially crafted
  office files causing remote code execution." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-003." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
func FileVer( file, path ){
	share = ereg_replace( pattern: "([A-Za-z]):.*", replace: "\\1$", string: path );
	if(IsMatchRegexp( share, "[a-z]\\$" )){
		share = toupper( share );
	}
	file = ereg_replace( pattern: "[A-Za-z]:(.*)", replace: "\\1", string: path + file );
	ver = GetVer( file: file, share: share );
	return ver;
}
officeVer = get_kb_item( "MS/Office/Ver" );
if(officeVer && IsMatchRegexp( officeVer, "^10\\." )){
	offPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(offPath){
		offPath += "\\Microsoft Shared\\OFFICE10";
		dllVer = FileVer( file: "\\Mso.dll", path: offPath );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "10.0", test_version2: "10.0.6857.9" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

