if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807513" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0121", "CVE-2016-0120" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-03-09 08:23:23 +0530 (Wed, 09 Mar 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Graphic Fonts Multiple Vulnerabilities (3143148)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-026." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to the Windows
  Adobe Type Manager Library improperly handles specially crafted OpenType
  fonts." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code. Failed exploit attempts will result in
  a denial-of-service condition." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3140735" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-026" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
userVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Atmfd.dll" );
if(!userVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1, win10: 1, win10x64: 1 ) > 0){
	if(version_is_less( version: userVer, test_version: "5.1.2.247" )){
		report = "File checked:     " + sysPath + "\\system32\\Atmfd.dll" + "\n" + "File version:     " + userVer + "\n" + "Vulnerable range: Less than 5.1.2.247\n";
		security_message( data: report );
		exit( 0 );
	}
}

