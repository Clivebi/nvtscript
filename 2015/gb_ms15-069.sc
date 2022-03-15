CPE = "cpe:/a:microsoft:rdp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805721" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-2368", "CVE-2015-2369" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-07-15 12:14:36 +0530 (Wed, 15 Jul 2015)" );
	script_name( "Microsoft Windows Remote Code Execution (3072631)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-069." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flows are due to improperly handling
  of the loading of dynamic link library (DLL) files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass security, gain elevated privileges and execute arbitrary
  code on affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows Server 2012 R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3072631" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS15-069" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_rdp_version_detect_win.sc" );
	script_mandatory_keys( "remote/desktop/protocol/Win/Installed" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/ms15-069.aspx" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win2012R2: 1, win8_1: 1, win8_1x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
CeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Cewmdm.dll" );
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Wcewmdm.dll" );
exeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Wksprt.exe" );
alVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Atlthunk.dll" );
alVer1 = fetch_file_version( sysPath: sysPath, file_name: "SysWOW64\\Atlthunk.dll" );
if(alVer1){
	alVer164 = sysPath + "\\SysWOW64\\Atlthunk.dll";
}
if(!CeVer && !dllVer && !exeVer && !alVer && !alVer1){
	exit( 0 );
}
rdpVer = get_app_version( cpe: CPE );
cleanPath = sysPath + "\\system32\\cleanmgr.exe";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: cleanPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: cleanPath );
exeSize = get_file_size( share: share, file: file );
if( hotfix_check_sp( win2003: 3 ) > 0 && CeVer ){
	if(version_is_less( version: CeVer, test_version: "10.0.3790.4011" )){
		Vulnerable_range = "Less than 10.0.3790.4011";
		VULN1 = TRUE;
	}
}
else {
	if( hotfix_check_sp( win2003x64: 3 ) > 0 && dllVer ){
		if(version_is_less( version: dllVer, test_version: "10.0.3790.4011" )){
			Vulnerable_range = "Less than 10.0.3790.4011";
			VULN2 = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( winVista: 3 ) > 0 && CeVer ){
			if( version_is_less( version: CeVer, test_version: "11.0.6002.19403" ) ){
				Vulnerable_range = "Less than 11.0.6002.19403";
				VULN1 = TRUE;
			}
			else {
				if(version_in_range( version: CeVer, test_version: "11.0.6002.23000", test_version2: "11.0.6002.23709" )){
					Vulnerable_range = "11.0.6002.23000 - 11.0.6002.23709";
					VULN1 = TRUE;
				}
			}
		}
		else {
			if( hotfix_check_sp( win2008: 3 ) > 0 && CeVer && exeSize ){
				if( version_is_less( version: CeVer, test_version: "11.0.6002.19403" ) ){
					Vulnerable_range = "Less than 11.0.6002.19403";
					VULN1 = TRUE;
				}
				else {
					if(version_in_range( version: CeVer, test_version: "11.0.6002.23000", test_version2: "11.0.6002.23709" )){
						Vulnerable_range = "11.0.6002.23000 - 11.0.6002.23709";
						VULN1 = TRUE;
					}
				}
			}
			else {
				if( hotfix_check_sp( win7: 2, win7x64: 2 ) > 0 ){
					if( version_in_range( version: rdpVer, test_version: "6.3.9600.00000", test_version2: "6.3.9600.99999" ) ){
						if(( exeVer && version_is_less( version: exeVer, test_version: "6.3.9600.17901" ) )){
							Vulnerable_range = "Less than 6.3.9600.17901";
							VULN3 = TRUE;
						}
					}
					else {
						if( CeVer && ( version_is_less( version: CeVer, test_version: "12.0.7601.18872" ) ) ){
							Vulnerable_range = "Less than 12.0.7601.18872";
							VULN1 = TRUE;
						}
						else {
							if(CeVer && ( version_in_range( version: CeVer, test_version: "12.0.7601.22000", test_version2: "12.0.7601.23074" ) )){
								Vulnerable_range = "12.0.7601.22000 - 12.0.7601.23074";
								VULN1 = TRUE;
							}
						}
					}
				}
				else {
					if( hotfix_check_sp( win2008r2: 2 ) > 0 ){
						if( version_in_range( version: rdpVer, test_version: "6.3.9600.00000", test_version2: "6.3.9600.99999" ) ){
							if(( exeVer && version_is_less( version: exeVer, test_version: "6.3.9600.17901" ) )){
								Vulnerable_range = "Less than 6.3.9600.17901";
								VULN3 = TRUE;
							}
						}
						else {
							if( CeVer && exeSize && ( version_is_less( version: CeVer, test_version: "12.0.7601.18872" ) ) ){
								Vulnerable_range = "Less than 12.0.7601.18872";
								VULN1 = TRUE;
							}
							else {
								if(CeVer && exeSize && ( version_in_range( version: CeVer, test_version: "12.0.7601.22000", test_version2: "12.0.7601.23074" ) )){
									Vulnerable_range = "12.0.7601.22000 - 12.0.7601.23074";
									VULN1 = TRUE;
								}
							}
						}
					}
					else {
						if( hotfix_check_sp( win8_1: 1 ) > 0 && alVer ){
							if(version_is_less( version: alVer, test_version: "6.3.9600.17415" )){
								Vulnerable_range = "Less than 6.3.9600.17415";
								VULN4 = TRUE;
							}
						}
						else {
							if(hotfix_check_sp( win8x64: 1, win2012: 1 ) > 0 && alVer1){
								if(version_is_less( version: alVer1, test_version: "6.3.9600.17670" )){
									Vulnerable_range = "Less than 6.3.9600.17670";
									VULN5 = TRUE;
								}
							}
						}
					}
				}
			}
		}
	}
}
if(VULN1){
	report = "File checked:     " + sysPath + "\\System32\\Cewmdm.dll" + "\n" + "File version:     " + CeVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
if(VULN2){
	report = "File checked:     " + sysPath + "\\System32\\Wcewmdm.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
if(VULN3){
	report = "File checked:     " + sysPath + "\\System32\\Wksprt.exe" + "\n" + "File version:     " + exeVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
if(VULN4){
	report = "File checked:     " + sysPath + "\\System32\\Atlthunk.dll" + "\n" + "File version:     " + alVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
if(VULN5){
	report = "File checked:     " + alVer164 + "\n" + "File version:     " + alVer1 + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

