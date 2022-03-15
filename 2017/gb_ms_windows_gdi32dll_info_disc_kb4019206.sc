if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811027" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_cve_id( "CVE-2017-0190" );
	script_bugtraq_id( 98297 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-05-10 09:58:52 +0530 (Wed, 10 May 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows 'GDI32.DLL' Information Disclosure Vulnerability (KB4019206)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4019206." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in the way that
  the Windows Graphics Device Interface (GDI) handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to retrieve information from a targeted system. By itself, the information
  disclosure does not allow arbitrary code execution. However, it could allow
  arbitrary code to be run if the attacker uses it in combination with another
  vulnerability." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4019206" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0190" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
gdiVer = fetch_file_version( sysPath: sysPath, file_name: "Gdi32.dll" );
if(!gdiVer){
	exit( 0 );
}
if( version_is_less( version: gdiVer, test_version: "6.0.6002.19765" ) ){
	Vulnerable_range = "Less than 6.0.6002.19765";
	VULN = TRUE;
}
else {
	if(version_in_range( version: gdiVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.24088" )){
		Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24088";
		VULN = TRUE;
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\Gdi32.dll" + "\n" + "File version:     " + gdiVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

