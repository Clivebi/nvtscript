CPE = "cpe:/a:microsoft:ie";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903329" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-3871", "CVE-2013-3908", "CVE-2013-3909", "CVE-2013-3910", "CVE-2013-3911", "CVE-2013-3912", "CVE-2013-3914", "CVE-2013-3915", "CVE-2013-3916", "CVE-2013-3917" );
	script_bugtraq_id( 63589, 63585, 63588, 63590, 63592, 63593, 63593, 63593, 63596, 63596 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-11-13 08:35:24 +0530 (Wed, 13 Nov 2013)" );
	script_name( "Microsoft Internet Explorer Multiple Vulnerabilities (2888505)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to Microsoft
  Bulletin MS13-088." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error when generating print previews of certain web content.

  - An error when handling CSS special characters.

  - An use-after-free error when handling CAnchorElement objects.

  - Multiple unspecified errors." );
	script_tag( name: "affected", value: "- Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x

  - Microsoft Internet Explorer version 11.x on Microsoft Windows 8.1 x32/x64 and Microsoft Windows server 2012 R2" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to corrupt memory by the
  execution of arbitrary code, disclose potentially sensitive information and compromise a user's system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2888505" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-088" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/IE/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win7: 2, win2008: 3, win8: 1, win8_1: 1 ) <= 0){
	exit( 0 );
}
ieVer = get_app_version( cpe: CPE );
if(!ieVer || !IsMatchRegexp( ieVer, "^([6-9|1[01])\\." )){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Mshtml.dll" );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "6.0.2900.6462" ) || version_in_range( version: dllVer, test_version: "7.0.6000.00000", test_version2: "7.0.6000.21358" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.23535" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win2003: 3 ) > 0 ){
		if(version_is_less( version: dllVer, test_version: "6.0.3790.5238" ) || version_in_range( version: dllVer, test_version: "7.0.6000.00000", test_version2: "7.0.6000.21358" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.23535" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
			if(version_in_range( version: dllVer, test_version: "7.0.6002.18000", test_version2: "7.0.6002.18960" ) || version_in_range( version: dllVer, test_version: "7.0.6002.22000", test_version2: "7.0.6002.23243" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.19482" ) || version_in_range( version: dllVer, test_version: "8.0.6001.20000", test_version2: "8.0.6001.23535" ) || version_in_range( version: dllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16519" ) || version_in_range( version: dllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20630" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if( hotfix_check_sp( win7: 2 ) > 0 ){
				if(version_in_range( version: dllVer, test_version: "8.0.7601.16000", test_version2: "8.0.7601.18282" ) || version_in_range( version: dllVer, test_version: "8.0.7601.21000", test_version2: "8.0.7601.22478" ) || version_in_range( version: dllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16519" ) || version_in_range( version: dllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20630" ) || version_in_range( version: dllVer, test_version: "10.0.9200.16000", test_version2: "10.0.9200.16735" ) || version_in_range( version: dllVer, test_version: "10.0.9200.20000", test_version2: "10.0.9200.20847" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			else {
				if( hotfix_check_sp( win8: 1 ) > 0 ){
					if(version_in_range( version: dllVer, test_version: "10.0.9200.16000", test_version2: "10.0.9200.16735" ) || version_in_range( version: dllVer, test_version: "10.0.9200.20000", test_version2: "10.0.9200.20847" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
				else {
					if(hotfix_check_sp( win8_1: 1 ) > 0){
						if(version_is_less( version: dllVer, test_version: "11.0.9431.224" )){
							security_message( port: 0, data: "The target host was found to be vulnerable" );
						}
						exit( 0 );
					}
				}
			}
		}
	}
}

