if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807339" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-3231" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-06-15 09:14:02 +0530 (Wed, 15 Jun 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows Diagnostic Hub Elevation of Privilege Vulnerability (3165479)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-078." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An elevation of privilege flaw exists
  when the Windows Diagnostics Hub Standard Collector Service fails to
  properly sanitize input, leading to an unsecure library loading behavior." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code with elevated system privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3163017" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3163018" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-078" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-078" );
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
	if( version_is_less( version: sysVer, test_version: "11.0.10240.16942" ) ){
		Vulnerable_range = "Less than 11.0.10240.16942";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: sysVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.419" )){
			Vulnerable_range = "11.0.10586.0 - 11.0.10586.419";
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

