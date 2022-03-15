if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807818" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-0149" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-05-11 08:22:52 +0530 (Wed, 11 May 2016)" );
	script_name( "Microsoft .NET Framework Information Disclosure Vulnerability (3156757)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-065." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to some unspecified
  error in the TLS/SSL protocol, implemented in the encryption component of
  Microsoft .NET Framework." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 2.0 Service Pack 2

  - Microsoft .NET Framework 3.5

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 4.5.2

  - Microsoft .NET Framework 4.6/4.6.1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3156757" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-065" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	dotPath = registry_get_sz( key: key + item, item: "Path" );
	if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
		sysdllVer = fetch_file_version( sysPath: dotPath, file_name: "System.dll" );
		if(sysdllVer){
			if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
				if( version_is_less( version: sysdllVer, test_version: "2.0.50727.4264" ) ){
					VULN = TRUE;
					vulnerable_range = "Less than 2.0.50727.4264";
				}
				else {
					if(version_in_range( version: sysdllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8685" )){
						VULN = TRUE;
						vulnerable_range = "2.0.50727.5700 - 2.0.50727.8685";
					}
				}
			}
			if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win8_1: 1, win8_1x64: 1, win2012R2: 1, win2012: 1 ) > 0 ){
				if(version_is_less( version: sysdllVer, test_version: "2.0.50727.8686" )){
					VULN = TRUE;
					vulnerable_range = "Less than 2.0.50727.8686";
				}
			}
			else {
				if( hotfix_check_sp( win2012: 1 ) > 0 ){
					if(version_in_range( version: sysdllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36349" )){
						VULN = TRUE;
						vulnerable_range = "4.0.30319.30000 - 4.0.30319.36349";
					}
				}
				else {
					if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0 ){
						if( version_in_range( version: sysdllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34293" ) ){
							VULN = TRUE;
							vulnerable_range = "4.0.30319.30000 - 4.0.30319.34293";
						}
						else {
							if(version_in_range( version: sysdllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36350" )){
								VULN = TRUE;
								vulnerable_range = "4.0.30319.36000 - 4.0.30319.36350";
							}
						}
					}
					else {
						if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
							if(version_in_range( version: sysdllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36349" )){
								VULN = TRUE;
								vulnerable_range = "4.0.30319.30000 - 4.0.30319.36349";
							}
						}
						else {
							if(hotfix_check_sp( win2012: 1, win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
								if(version_in_range( version: sysdllVer, test_version: "4.6", test_version2: "4.6.1074" )){
									VULN = TRUE;
									vulnerable_range = "4.6 - 4.6.1074";
								}
							}
						}
					}
				}
			}
			key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
			if(!registry_key_exists( key: key )){
				exit( 0 );
			}
			win10ver = registry_get_sz( key: key, item: "ReleaseID" );
			if(win10ver && ContainsString( win10ver, "1511" )){
				win10_1511 = TRUE;
			}
			if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
				if( win10_1511 ){
					if(version_is_less( version: sysdllVer, test_version: "2.0.50727.8690" )){
						vulnerable_range = "Less than 2.0.50727.8690";
						VULN = TRUE;
					}
					if(version_in_range( version: sysdllVer, test_version: "4.6", test_version2: "4.6.1080" )){
						VULN = TRUE;
						vulnerable_range = "4.6 - 4.6.1080";
					}
				}
				else {
					if(version_is_less( version: sysdllVer, test_version: "2.0.50727.8686" )){
						vulnerable_range = "Less than 2.0.50727.8686";
						VULN = TRUE;
					}
					if(version_in_range( version: sysdllVer, test_version: "4.6", test_version2: "4.6.1074" )){
						VULN = TRUE;
						vulnerable_range = "4.6 - 4.6.1074";
					}
				}
			}
		}
	}
	if(VULN){
		report = "File checked:     " + dotPath + "\\System.dll" + "\n" + "File version:     " + sysdllVer + "\n" + "Vulnerable range: " + vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

