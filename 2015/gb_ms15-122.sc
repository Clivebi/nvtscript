if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806556" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-6095" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:C/A:N" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-11-11 08:59:53 +0530 (Wed, 11 Nov 2015)" );
	script_name( "Microsoft Windows Kerberos Local Security Bypass Vulnerability (3105256)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-122." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to Kerberos fails to check
  the password change of a user signing into a workstation." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attackers to bypass certain security restrictions and perform unauthorized
  actions." );
	script_tag( name: "affected", value: "- Microsoft Windows 8 x32/x64

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3105256" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-122" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "System32\\kerberos.dll" );
if(!dllVer){
	exit( 0 );
}
if( IsMatchRegexp( dllVer, "^(6\\.0\\.6002\\.1)" ) ){
	Vulnerable_range = "Less than 6.0.6002.19525";
}
else {
	if( IsMatchRegexp( dllVer, "^(6\\.0\\.6002\\.2)" ) ){
		Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23834";
	}
	else {
		if( IsMatchRegexp( dllVer, "^(6\\.1\\.7601\\.2)" ) ){
			Vulnerable_range = "6.1.7601.23000 - 6.1.7601.23248";
		}
		else {
			if( IsMatchRegexp( dllVer, "^(6\\.1\\.7601\\.1)" ) ){
				Vulnerable_range = "Less than 6.1.7601.19043";
			}
			else {
				if( IsMatchRegexp( dllVer, "^(6\\.2\\.9200\\.1)" ) ){
					Vulnerable_range = "Less than 6.2.9200.17557";
				}
				else {
					if( IsMatchRegexp( dllVer, "^(6\\.2\\.9200\\.2)" ) ){
						Vulnerable_range = "6.2.9200.21000 - 6.2.9200.21673";
					}
					else {
						if(IsMatchRegexp( dllVer, "^(6\\.3\\.9600\\.1)" )){
							Vulnerable_range = "Less than 6.3.9600.18091";
						}
					}
				}
			}
		}
	}
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "6.0.6002.19525" ) || version_in_range( version: dllVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23834" )){
		VULN = TRUE;
	}
}
else {
	if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
		if(version_is_less( version: dllVer, test_version: "6.1.7601.19043" ) || version_in_range( version: dllVer, test_version: "6.1.7601.23000", test_version2: "6.1.7601.23248" )){
			VULN = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ){
			if(version_is_less( version: dllVer, test_version: "6.2.9200.17557" ) || version_in_range( version: dllVer, test_version: "6.2.9200.21000", test_version2: "6.2.9200.21673" )){
				VULN = TRUE;
			}
		}
		else {
			if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
				if(version_is_less( version: dllVer, test_version: "6.3.9600.18091" )){
					VULN = TRUE;
				}
			}
			else {
				if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
					if(version_is_less( version: dllVer, test_version: "10.0.10240.16590" )){
						Vulnerable_range = "Less than 10.0.10240.16590";
						VULN = TRUE;
					}
					if(version_in_range( version: dllVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.2" )){
						Vulnerable_range = "10.0.10586.0 - 10.0.10586.2";
						VULN = TRUE;
					}
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\system32\\Kerberos.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

