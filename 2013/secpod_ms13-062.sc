if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903317" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-3175" );
	script_bugtraq_id( 61673 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-08-14 12:08:17 +0530 (Wed, 14 Aug 2013)" );
	script_name( "Microsoft Windows NAT Driver Denial of Service Vulnerability (2849568)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to Microsoft
  Bulletin MS13-062." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Flaw is due to an improper handling asynchronous RPC requests." );
	script_tag( name: "affected", value: "- Microsoft Windows 8

  - Microsoft Windows Server 2012

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code and
  take complete control of an affected system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-062" );
	script_xref( name: "URL", value: "http://support.microsoft.com/default.aspx?scid=kb;EN-US;2849470" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win2012: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Rpcrt4.dll" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "5.1.2600.6399" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win2003: 3, xpx64: 3, win2003x64: 3 ) > 0 ){
		if(version_is_less( version: sysVer, test_version: "5.2.3790.5194" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
			if(version_is_less( version: sysVer, test_version: "6.0.6002.18882" ) || version_in_range( version: sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.23154" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
				if(version_is_less( version: sysVer, test_version: "6.1.7601.18205" ) || version_in_range( version: sysVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.22379" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			else {
				if(hotfix_check_sp( win8: 1, win2012: 1 ) > 0){
					if(version_is_less( version: sysVer, test_version: "6.2.9200.16622" ) || version_in_range( version: sysVer, test_version: "6.2.9200.20000", test_version2: "6.2.9200.20726" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
			}
		}
	}
}

