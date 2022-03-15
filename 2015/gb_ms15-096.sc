if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806044" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2015-2535" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-09-09 08:24:16 +0530 (Wed, 09 Sep 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "MS Windows Active Directory Service Denial of Service Vulnerability (3072595)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-096." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper resource
  management by the affected software while creating multiple machine accounts." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  the attacker to cause the service to become non-responsive, resulting in
  denial-of-service conditions." );
	script_tag( name: "affected", value: "- Microsoft Windows Server 2012

  - Microsoft Windows Server 2012R2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3072595" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-096" );
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
if(hotfix_check_sp( win2008: 3, win2008r2: 2, win2012: 1, win2012R2: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Samsrv.dll" );
if(!dllVer){
	exit( 0 );
}
if( IsMatchRegexp( dllVer, "^(6\\.0\\.6002\\.1)" ) ){
	Vulnerable_range = "6.0.6002.18000 - 6.0.6002.19467";
}
else {
	if( IsMatchRegexp( dllVer, "^(6\\.0\\.6002\\.2)" ) ){
		Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23776";
	}
	else {
		if( IsMatchRegexp( dllVer, "^(6\\.1\\.7601\\.1)" ) ){
			Vulnerable_range = "6.1.7601.18000 - 6.1.7601.18956";
		}
		else {
			if( IsMatchRegexp( dllVer, "^(6\\.1\\.7601\\.2)" ) ){
				Vulnerable_range = "6.1.7601.22000 - 6.1.7601.23158";
			}
			else {
				if( IsMatchRegexp( dllVer, "^(6\\.2\\.9200\\.1)" ) ){
					Vulnerable_range = "6.2.9200.16000 - 6.2.9200.17469";
				}
				else {
					if( IsMatchRegexp( dllVer, "^(6\\.2\\.9200\\.2)" ) ){
						Vulnerable_range = "6.2.9200.20000 - 6.2.9200.21584";
					}
					else {
						if(IsMatchRegexp( dllVer, "^(6\\.3\\.9200\\.1)" )){
							Vulnerable_range = "6.3.9200.16000 - 6.3.9600.18009";
						}
					}
				}
			}
		}
	}
}
if(hotfix_check_sp( win2008: 3 ) > 0){
	if(version_is_less( version: dllVer, test_version: "6.0.6002.19467" ) || version_in_range( version: dllVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23776" )){
		VULN = TRUE;
	}
}
if(hotfix_check_sp( win2008r2: 2 ) > 0){
	if(version_is_less( version: dllVer, test_version: "6.1.7601.18956" ) || version_in_range( version: dllVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.23158" )){
		VULN = TRUE;
	}
}
if(hotfix_check_sp( win2012: 1 ) > 0){
	if(version_is_less( version: dllVer, test_version: "6.2.9200.17469" ) || version_in_range( version: dllVer, test_version: "6.2.9200.20000", test_version2: "6.2.9200.21584" )){
		VULN = TRUE;
	}
}
if(hotfix_check_sp( win2012R2: 1 ) > 0){
	if(version_is_less( version: dllVer, test_version: "6.3.9600.18009" )){
		VULN = TRUE;
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\system32\\Samsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

