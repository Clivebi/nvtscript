CPE = "cpe:/a:microsoft:ie";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805163" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-1652", "CVE-2015-1657", "CVE-2015-1659", "CVE-2015-1660", "CVE-2015-1661", "CVE-2015-1662", "CVE-2015-1665", "CVE-2015-1666", "CVE-2015-1667", "CVE-2015-1668" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-04-15 08:46:55 +0530 (Wed, 15 Apr 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Internet Explorer Multiple Memory Corruption Vulnerabilities (3038314)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS15-032." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to improper
  handling memory objects when accessing it and some user-supplied input
  is not properly validated." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to corrupt memory and potentially execute arbitrary code in the
  context of the current user." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x/11.x and VBScript 5.8 on IE 8.x/9.x/10.x/11.x." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3038314" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-032" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/IE/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1 ) <= 0){
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
if( hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "6.0.3790.5569" ) || version_in_range( version: dllVer, test_version: "7.0.6000.00000", test_version2: "7.0.6000.21447" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.23670" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
		if(version_in_range( version: dllVer, test_version: "7.0.6002.18000", test_version2: "7.0.6002.19333" ) || version_in_range( version: dllVer, test_version: "7.0.6002.23000", test_version2: "7.0.6002.23641" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.19611" ) || version_in_range( version: dllVer, test_version: "8.0.6001.20000", test_version2: "8.0.6001.23670" ) || version_in_range( version: dllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16635" ) || version_in_range( version: dllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20749" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
			if(version_in_range( version: dllVer, test_version: "8.0.7601.17000", test_version2: "8.0.7601.18805" ) || version_in_range( version: dllVer, test_version: "8.0.7601.22000", test_version2: "8.0.7601.23009" ) || version_in_range( version: dllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16635" ) || version_in_range( version: dllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20749" ) || version_in_range( version: dllVer, test_version: "10.0.9200.16000", test_version2: "10.0.9200.17295" ) || version_in_range( version: dllVer, test_version: "10.0.9200.21000", test_version2: "10.0.9200.21412" ) || version_in_range( version: dllVer, test_version: "11.0.9600.00000", test_version2: "11.0.9600.17727" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ){
				if(version_in_range( version: dllVer, test_version: "10.0.9200.16000", test_version2: "10.0.9200.17295" ) || version_in_range( version: dllVer, test_version: "10.0.9200.20000", test_version2: "10.0.9200.21412" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			else {
				if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
					if(version_is_less( version: dllVer, test_version: "11.0.9600.17727" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
			}
		}
	}
}
exit( 99 );

