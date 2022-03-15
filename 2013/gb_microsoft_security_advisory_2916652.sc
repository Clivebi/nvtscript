if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803978" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2013-12-10 17:56:31 +0530 (Tue, 10 Dec 2013)" );
	script_name( "Microsoft Digital Certificates Security Advisory (2916652)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to Microsoft
  advisory (2916652)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "The flaw is due to DG Tresor which improperly issued a subordinate CA
  certificate" );
	script_tag( name: "affected", value: "- Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to spoof content, perform
  phishing attacks, or perform man-in-the-middle attacks." );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2677070" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/advisory/2916652" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_smb_windows_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
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
exeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Crypt32.dll" );
if( !exeVer ){
	exit( 0 );
}
else {
	if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
		if(version_is_less( version: exeVer, test_version: "6.0.6002.18618" ) || version_in_range( version: exeVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22839" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}
if(hotfix_check_sp( win7: 2, win7x64: 2 ) > 0){
	if(version_is_less( version: exeVer, test_version: "6.1.7600.17008" ) || version_in_range( version: exeVer, test_version: "6.1.7601.21000", test_version2: "6.1.7600.21198" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win2008r2: 2 ) > 0){
	if(version_in_range( version: exeVer, test_version: "6.1.7600.16000", test_version2: "6.1.7600.17007" ) || version_in_range( version: exeVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21198" ) || version_in_range( version: exeVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17826" ) || version_in_range( version: exeVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21978" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}

