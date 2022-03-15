if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808085" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-3213", "CVE-2016-3236", "CVE-2016-3299" );
	script_bugtraq_id( 91111, 92387, 91114 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-06-15 08:55:09 +0530 (Wed, 15 Jun 2016)" );
	script_name( "Microsoft Web Proxy Auto Discovery (WPAD) Privilege Elevation Vulnerabilities (3165191)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-077." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - when the Web Proxy Auto Discovery (WPAD) protocol falls back to
    a vulnerable proxy discovery process.

  - when Microsoft Windows improperly handles certain proxy discovery
    scenarios using the Web Proxy Auto Discovery (WPAD) protocol method.

  - when NetBIOS improperly handles responses." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to bypass security and gain elevated privileges on a targeted
  system, and to potentially access and control network traffic for which
  the attacker does not have sufficient privileges." );
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
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3165191" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-077" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "System32\\Ws2_32.dll" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "6.1.7601.23451" )){
		Vulnerable_range = "Less than 6.1.7601.23451";
		VULN = TRUE;
	}
}
else {
	if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
		if( version_is_less( version: sysVer, test_version: "6.0.6002.19655" ) ){
			Vulnerable_range = "Less than 6.0.6002.19655";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: sysVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23969" )){
				Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23969";
				VULN = TRUE;
			}
		}
	}
	else {
		if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
			if(version_is_less( version: sysVer, test_version: "6.3.9600.18340" )){
				Vulnerable_range = "Less than 6.3.9600.18340";
				VULN = TRUE;
			}
		}
		else {
			if( hotfix_check_sp( win2012: 1 ) > 0 ){
				if(version_is_less( version: sysVer, test_version: "6.2.9200.21858" )){
					Vulnerable_range = "Less than 6.2.9200.21858";
					VULN = TRUE;
				}
			}
			else {
				if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
					if( version_is_less( version: sysVer, test_version: "10.0.10240.16942" ) ){
						Vulnerable_range = "Less than 10.0.10240.16942";
						VULN = TRUE;
					}
					else {
						if(version_in_range( version: sysVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.419" )){
							Vulnerable_range = "10.0.10586.0 - 10.0.10586.419";
							VULN = TRUE;
						}
					}
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\System32\\Ws2_32.dll" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

