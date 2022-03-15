if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818162" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-34527" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-14 18:15:00 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-09 11:39:50 +0530 (Fri, 09 Jul 2021)" );
	script_name( "Microsoft Windows Print Spooler RCE Vulnerability (KB5005010, PrintNightmare)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft KB5005010. The flaw is dubbed 'PrintNightmare'." );
	script_tag( name: "vuldetect", value: "Check if a vulnerable file and registry configuration is
  present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the Microsoft Windows Print Spooler service
  which fails to restrict access to functionality that allows users to add printers and related
  drivers." );
	script_tag( name: "impact", value: "Successful exploitation allow attackers to execute arbitrary code
  with SYSTEM privileges on a vulnerable system." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2019

  - Microsoft Windows Server 2016

  - Microsoft Windows 7 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2008 x32

  - Microsoft Windows Server 2008 R2 x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2" );
	script_tag( name: "solution", value: "The vendor has released updates.

  In addition to installing the updates users are recommended to either disable the Print Spooler
  service, or to Disable inbound remote printing through Group Policy.

  Please see the references for more information." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/5005010" );
	script_xref( name: "URL", value: "https://msrc-blog.microsoft.com/2021/07/08/clarified-guidance-for-cve-2021-34527-windows-print-spooler-vulnerability/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1, win2016: 1, win2008: 3, win2019: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "spoolsv.exe" );
dllVer = fetch_file_version( sysPath: sysPath, file_name: "win32spl.dll" );
if(!exeVer && !dllVer){
	exit( 0 );
}
if( hotfix_check_sp( win2012: 1 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "6.2.9200.23381" )){
		report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.2.9200.23381" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
		if(version_is_less( version: exeVer, test_version: "6.3.9600.20046" )){
			fix = "6.3.9600.20046";
		}
	}
	else {
		if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
			if(version_is_less( version: exeVer, test_version: "6.1.7601.25633" )){
				fix = "6.1.7601.25633";
			}
		}
		else {
			if( hotfix_check_sp( win2008: 3 ) > 0 ){
				if(version_is_less( version: exeVer, test_version: "6.0.6003.21138" )){
					fix = "6.0.6003.21138";
				}
			}
			else {
				if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
					if( version_in_range( version: exeVer, test_version: "10.0.14393.0", test_version2: "10.0.14393.4469" ) ){
						fix = "10.0.14393.4470";
					}
					else {
						if( version_in_range( version: exeVer, test_version: "10.0.10240.0", test_version2: "10.0.10240.18968" ) ){
							fix = "10.0.10240.18969";
						}
						else {
							if( version_in_range( version: exeVer, test_version: "10.0.19041.0", test_version2: "10.0.19041.1082" ) ){
								fix = "10.0.19041.1083";
							}
							else {
								if( version_in_range( version: exeVer, test_version: "10.0.18362.0", test_version2: "10.0.18362.1645" ) ){
									fix = "10.0.18362.1646";
								}
								else {
									if(version_in_range( version: exeVer, test_version: "10.0.17763.0", test_version2: "10.0.17763.2028" )){
										fix = "10.0.17763.2029";
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: exeVer, fixed_version: fix );
	report += "\nIn order to secure your system, please also confirm that the following registry keys are set to 0 (zero) or are not present:\n";
	report += "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint";
	report += "\n - NoWarningNoElevationOnInstall = 0 (DWORD) or not defined (default setting)";
	report += "\n - UpdatePromptSettings = 0 (DWORD) or not defined (default setting)";
	security_message( port: 0, data: report );
	exit( 0 );
}
key = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint";
if(registry_key_exists( key: key )){
	subkey1 = "NoWarningNoElevationOnInstall";
	value1 = registry_get_dword( key: key, item: subkey1 );
	subkey2 = "UpdatePromptSettings";
	value2 = registry_get_dword( key: key, item: subkey2 );
}
if(( value1 || value2 ) && ( value1 == "1" || value2 == "1" )){
	report = "The following registry keys (key!subkey:value) are set to \"1\" making the system vulnerable against PrintNightmare even if the referenced patch has been applied:\n";
	if(value1 == "1"){
		report += "\n" + "HKLM\\" + key + "!" + subkey1 + ":" + value1;
	}
	if(value2 == "1"){
		report += "\n" + "HKLM\\" + key + "!" + subkey2 + ":" + value2;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

