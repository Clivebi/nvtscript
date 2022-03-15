if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805774" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-2478" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-11-11 08:52:04 +0530 (Wed, 11 Nov 2015)" );
	script_name( "MS Windows Winsock Elevation of Privilege Vulnerability (3104521)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-119." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to a double-free error in the
  Ancillary Function Driver within 'afd.sys'." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain elevated privileges of an affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2

  - Microsoft Edge on Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3092601" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms15-119" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows : Microsoft Bulletins" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
afdSysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Drivers\\afd.sys" );
if(!afdSysVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	if( version_is_less( version: afdSysVer, test_version: "6.0.6002.19513" ) ){
		Vulnerable_range = "Less than 6.0.6002.19513";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: afdSysVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23822" )){
			Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23822";
			VULN = TRUE;
		}
	}
}
else {
	if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
		if( version_is_less( version: afdSysVer, test_version: "6.1.7601.19031" ) ){
			Vulnerable_range = "less than 6.1.7601.19031";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: afdSysVer, test_version: "6.1.7601.23000", test_version2: "6.1.7601.23236" )){
				Vulnerable_range = "6.1.7601.23000 - 6.1.7601.23236";
				VULN = TRUE;
			}
		}
	}
	else {
		if( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ){
			if( version_is_less( version: afdSysVer, test_version: "6.2.9200.17540" ) ){
				Vulnerable_range = "Less than  6.2.9200.17540";
				VULN = TRUE;
			}
			else {
				if(version_in_range( version: afdSysVer, test_version: "6.2.9200.21000", test_version2: "6.2.9200.21656" )){
					Vulnerable_range = "6.2.9200.21000 - 6.2.9200.21656";
					VULN = TRUE;
				}
			}
		}
		else {
			if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
				if(version_is_less( version: afdSysVer, test_version: "6.3.9600.18089" )){
					Vulnerable_range = "Less than 6.3.9600.18089";
					VULN = TRUE;
				}
			}
			else {
				if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
					if( version_is_less( version: afdSysVer, test_version: "10.0.10240.16590" ) ){
						Vulnerable_range = "Less than 10.0.10240.16590";
						VULN = TRUE;
					}
					else {
						if(version_in_range( version: afdSysVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.2" )){
							Vulnerable_range = "10.0.10586.0 - 10.0.10586.2";
							VULN = TRUE;
						}
					}
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "system32\\Drivers\\afd.sys" + "\n" + "File version:     " + afdSysVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
