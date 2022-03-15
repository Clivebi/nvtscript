if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808784" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-3308", "CVE-2016-3309", "CVE-2016-3310", "CVE-2016-3311" );
	script_bugtraq_id( 92295, 92297, 92298, 92299 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-08-10 08:16:35 +0530 (Wed, 10 Aug 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Kernel-Mode Drivers Multiple Privilege Elevation Vulnerabilities (3178466)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-098." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist when the Windows
  kernel-mode driver fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to run arbitrary code in kernel mode, and obtain information to
  further compromise the user's system." );
	script_tag( name: "affected", value: "- Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3178466" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-098" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-098" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, winVistax64: 3, win7: 2, win7x64: 2, win2008: 3, win2008x64: 3, win2008r2: 2, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "System32\\Win32k.sys" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "6.3.9600.18405" )){
		Vulnerable_range = "Less than 6.3.9600.18405";
		VULN = TRUE;
	}
}
else {
	if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
		if(version_is_less( version: sysVer, test_version: "6.1.7601.23497" )){
			Vulnerable_range = "Less than 6.1.7601.23497";
			VULN = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( win2012: 1 ) > 0 ){
			if(version_is_less( version: sysVer, test_version: "6.2.9200.21926" )){
				Vulnerable_range = "Less than 6.2.9200.21926";
				VULN = TRUE;
			}
		}
		else {
			if( hotfix_check_sp( winVista: 3, winVistax64: 3, win2008: 3, win2008x64: 3 ) > 0 ){
				if( version_is_less( version: sysVer, test_version: "6.0.6002.19668" ) ){
					Vulnerable_range = "Less than 6.0.6002.19668";
					VULN = TRUE;
				}
				else {
					if(version_in_range( version: sysVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23983" )){
						Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23983";
						VULN = TRUE;
					}
				}
			}
			else {
				if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
					if( version_is_less( version: sysVer, test_version: "10.0.10240.16384" ) ){
						Vulnerable_range = "Less than 10.0.10240.16384";
						VULN = TRUE;
					}
					else {
						if(version_in_range( version: sysVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.19" )){
							Vulnerable_range = "10.0.10586.0 - 10.0.10586.19";
							VULN = TRUE;
						}
					}
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\System32\\Win32k.sys" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

