if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808019" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0182" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-05-11 10:37:53 +0530 (Wed, 11 May 2016)" );
	script_name( "Microsoft Windows Journal Memory Corruption Vulnerability (3156761)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-056." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error
  within Windows Journal while parsing Journal files." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct denial-of-service attack or execute arbitrary code in the context
  of the currently logged-in user and compromise a user's system." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3156761" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-056" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win8_1: 1, win8_1x64: 1, win2008: 3, win10: 1, win10x64: 1, win2012R2: 1, win2012: 1, win2008r2: 2 ) <= 0){
	exit( 0 );
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!sysPath){
	exit( 0 );
}
sysPath = sysPath + "\\Windows Journal";
dllVer = fetch_file_version( sysPath: sysPath, file_name: "Inkseg.dll" );
if(!dllVer){
	exit( 0 );
}
if( IsMatchRegexp( dllVer, "^(6\\.3\\.9600\\.1)" ) ){
	Vulnerable_range = "Less than 6.3.9600.18294";
}
else {
	if( IsMatchRegexp( dllVer, "^(6\\.1\\.7601\\.2)" ) ){
		Vulnerable_range = "Less than 6.1.7601.23415";
	}
	else {
		if( IsMatchRegexp( dllVer, "^(6\\.0\\.6002\\.19634)" ) ){
			Vulnerable_range = "Less than 6.0.6002.19634";
		}
		else {
			if(IsMatchRegexp( dllVer, "^(6\\.0\\.6002\\.2)" )){
				Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23947";
			}
		}
	}
}
if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "6.1.7601.23415" )){
		VULN = TRUE;
	}
}
else {
	if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
		if(version_is_less( version: dllVer, test_version: "6.3.9600.18294" )){
			VULN = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( win2012: 1 ) > 0 ){
			if(version_is_less( version: dllVer, test_version: "6.2.9200.21830" )){
				Vulnerable_range = "Less than 6.2.9200.21830";
				VULN = TRUE;
			}
		}
		else {
			if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
				if(version_is_less( version: dllVer, test_version: "6.0.6002.19634" ) || version_in_range( version: dllVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23947" )){
					VULN = TRUE;
				}
			}
		}
	}
}
if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
	if( version_is_less( version: dllVer, test_version: "10.0.10240.16683" ) ){
		Vulnerable_range = "Less than 10.0.10240.16683";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: dllVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.121" )){
			Vulnerable_range = "10.0.10586.0 - 10.0.10586.121";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\Inkseg.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

