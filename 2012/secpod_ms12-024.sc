if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902669" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-0151" );
	script_bugtraq_id( 52317 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-04-11 09:37:03 +0530 (Wed, 11 Apr 2012)" );
	script_name( "Windows Authenticode Signature Remote Code Execution Vulnerability (2653956)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2653956" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-024" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code as the logged-on user." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to the way Windows Authenticode Signature Verification
  function verifies portable executable (PE) files, which can be exploited to
  add malicious code to the file without invalidating the signature." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS12-024." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Wintrust.dll" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "5.131.2600.6198" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win2003: 3, xpx64: 3, win2003x64: 3 ) > 0 ){
		if(version_is_less( version: sysVer, test_version: "5.131.3790.4970" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
			if(version_is_less( version: sysVer, test_version: "6.0.6002.18592" ) || version_in_range( version: sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22805" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_is_less( version: sysVer, test_version: "6.1.7600.16970" ) || version_in_range( version: sysVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21159" ) || version_in_range( version: sysVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17786" ) || version_in_range( version: sysVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21932" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

