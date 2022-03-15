if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807693" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-0181" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-05-11 19:18:46 +0530 (Wed, 11 May 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows Virtual Secure Mode Security Feature Bypass vulnerability (3155451)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-066." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A security feature bypass vulnerability exists
  when Windows incorrectly allows certain kernel-mode pages to be marked as Read, Write,
  Execute (RWX) even with Hypervisor Code Integrity (HVCI) enabled." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to bypass a security feature." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3156387" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3156421" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-066" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(!sysVer){
	exit( 0 );
}
if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
	if( version_is_less( version: sysVer, test_version: "11.0.10240.16841" ) ){
		Vulnerable_range = "Less than 11.0.10240.16841";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: sysVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.305" )){
			Vulnerable_range = "11.0.10586.0 - 11.0.10586.305";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\edgehtml.dll" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

