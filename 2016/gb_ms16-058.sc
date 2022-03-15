if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807323" );
	script_version( "2020-11-12T09:36:23+0000" );
	script_cve_id( "CVE-2016-0152" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-05-11 08:26:16 +0530 (Wed, 11 May 2016)" );
	script_name( "Microsoft Windows IIS Remote Code Execution Vulnerability (3141083)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-058." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A remote code execution flaw exists when
  Microsoft Windows fails to properly validate input before loading certain
  libraries." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently
  logged-in user." );
	script_tag( name: "affected", value: "- Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3141083" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3141083" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-058" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_ms_iis_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/IIS/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
iisVer = get_kb_item( "MS/IIS/Ver" );
if(!iisVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\inetsrv\\Aspnetca.exe" );
if(!dllVer){
	exit( 0 );
}
if( IsMatchRegexp( dllVer, "^(7\\.0\\.6002\\.1)" ) ){
	Vulnerable_range = "Less than 7.0.6002.19634";
}
else {
	if(IsMatchRegexp( dllVer, "^(7\\.0\\.6002\\.2)" )){
		Vulnerable_range = "7.0.6002.23000 - 7.0.6002.23947";
	}
}
if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
	if(( version_is_less( version: dllVer, test_version: "7.0.6002.19634" ) ) || ( version_in_range( version: dllVer, test_version: "7.0.6002.23000", test_version2: "7.0.6002.23947" ) )){
		report = "File checked:     " + sysPath + "\\system32\\inetsrv\\Aspnetca.exe" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
