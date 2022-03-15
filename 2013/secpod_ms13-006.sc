if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901214" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-0013" );
	script_bugtraq_id( 57144 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-01-09 12:04:09 +0530 (Wed, 09 Jan 2013)" );
	script_name( "Microsoft Windows Security Feature Bypass Vulnerability (2785220)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2785220" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-006" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_smb_windows_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to silently downgrade
  a SSL version 3 or TLS connection to SSL version 2, which supports weak
  encryption cyphers." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The vulnerability is caused when Windows fails to properly handle SSL/TLS
  session version negotiation." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-006." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Ncrypt.dll" );
if(!exeVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	if(version_is_less( version: exeVer, test_version: "6.0.6002.18736" ) || version_in_range( version: exeVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22980" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
		if(version_is_less( version: exeVer, test_version: "6.1.7600.17172" ) || version_in_range( version: exeVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21376" ) || version_in_range( version: exeVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.18006" ) || version_in_range( version: exeVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.22168" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

