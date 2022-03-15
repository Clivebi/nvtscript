CPE = "cpe:/a:microsoft:ie";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808645" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-3288", "CVE-2016-3289", "CVE-2016-3290", "CVE-2016-3293", "CVE-2016-3321", "CVE-2016-3322", "CVE-2016-3326", "CVE-2016-3327", "CVE-2016-3329" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-08-10 08:20:58 +0530 (Wed, 10 Aug 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Internet Explorer Multiple Vulnerabilities (3177356)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-095." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - An improper access of objects in memory.

  - An improper handling of page content." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the current user, also
  could gain the same user rights as the current user, and obtain information
  to further compromise the user's system." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 9.x/10.x/11.x." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3177356" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-095" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, winVistax64: 3, win2008x64: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
ieVer = get_app_version( cpe: CPE );
if(!ieVer || !IsMatchRegexp( ieVer, "^(9|1[01])\\." )){
	exit( 0 );
}
iePath = smb_get_systemroot();
if(!iePath){
	exit( 0 );
}
iedllVer = fetch_file_version( sysPath: iePath, file_name: "system32\\Mshtml.dll" );
if(!iedllVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3, win2008: 3, winVistax64: 3, win2008x64: 3 ) > 0 ){
	if( version_in_range( version: iedllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16810" ) ){
		Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16810";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: iedllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20926" )){
			Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20926";
			VULN = TRUE;
		}
	}
}
else {
	if( hotfix_check_sp( win2012: 1 ) > 0 ){
		if(version_in_range( version: iedllVer, test_version: "10.0.9200.16000", test_version2: "10.0.9200.21925" )){
			Vulnerable_range = "10.0.9200.16000 - 10.0.9200.21925";
			VULN = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
			if(version_in_range( version: iedllVer, test_version: "11.0.9600.00000", test_version2: "11.0.9600.18426" )){
				Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18426";
				VULN = TRUE;
			}
		}
		else {
			if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
				if(version_in_range( version: iedllVer, test_version: "11.0.9600.00000", test_version2: "11.0.9600.18426" )){
					Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18426";
					VULN = TRUE;
				}
			}
			else {
				if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
					if( version_in_range( version: iedllVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.544" ) ){
						Vulnerable_range = "11.0.10586.0 - 11.0.10586.544";
						VULN = TRUE;
					}
					else {
						if(version_is_less( version: iedllVer, test_version: "11.0.10240.17071" )){
							Vulnerable_range = "Less than 11.0.10240.17071";
							VULN = TRUE;
						}
					}
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + iePath + "\\system32\\Mshtml.dll" + "\n" + "File version:     " + iedllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

