if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807790" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0151" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-04-13 08:06:29 +0530 (Wed, 13 Apr 2016)" );
	script_name( "Microsoft Windows CSRSS Feature Bypass Vulnerability (3148528)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-048" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in Microsoft Windows when the
  Client-Server Run-time Subsystem (CSRSS) fails to properly manage process
  tokens in memory" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code as an administrator." );
	script_tag( name: "affected", value: "- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3146723" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3147461" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3147458" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-048" );
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
if(hotfix_check_sp( win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "System32\\Ntoskrnl.exe" );
if(!sysVer){
	exit( 0 );
}
if( IsMatchRegexp( sysVer, "^(6\\.3\\.9600\\.1)" ) ){
	Vulnerable_range = "Less than 6.3.9600.18258";
}
else {
	if(IsMatchRegexp( sysVer, "^(6\\.2\\.9200\\.2)" )){
		Vulnerable_range = "Less than 6.2.9200.21821";
	}
}
if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "6.3.9600.18258" )){
		VULN = TRUE;
	}
}
else {
	if( hotfix_check_sp( win2012: 1 ) > 0 ){
		if(version_is_less( version: sysVer, test_version: "6.2.9200.21821" )){
			VULN = TRUE;
		}
	}
	else {
		if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
			if( version_is_less( version: sysVer, test_version: "10.0.10240.16724" ) ){
				Vulnerable_range = "10.0.10240.16724";
				VULN = TRUE;
			}
			else {
				if(version_in_range( version: sysVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.211" )){
					Vulnerable_range = "10.0.10586.0 - 10.0.10586.211";
					VULN = TRUE;
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\system32\\Ntoskrnl.exe" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

