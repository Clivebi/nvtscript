if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107144" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_cve_id( "CVE-2017-0045" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-03-15 08:10:02 +0530 (Wed, 15 Mar 2017)" );
	script_name( "Microsoft Windows DVD Maker Cross-Site Request Forgery Vulnerability (3208223)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS17-020." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Windows DVD Maker fails
  to properly parse a specially crafted '.msdvd' file." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to obtain information to further compromise a target system." );
	script_tag( name: "affected", value: "- Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3208223" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS17-020" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, winVistax64: 3 ) <= 0){
	exit( 0 );
}
if(!path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" )){
	exit( 0 );
}
filepath = path + "\\DVD Maker";
file1path = path + "\\Movie Maker";
if( hotfix_check_sp( win7: 2, win7x64: 2 ) > 0 ){
	dvdVer = fetch_file_version( sysPath: filepath, file_name: "DVDMaker.exe" );
	if(dvdVer && version_is_less( version: dvdVer, test_version: "6.1.7601.23656" )){
		Vulnerable_range = "Less than 6.1.7601.23656";
		VULN1 = TRUE;
	}
}
else {
	if(hotfix_check_sp( winVista: 3, winVistax64: 3 ) > 0){
		dvdVer1 = fetch_file_version( sysPath: file1path, file_name: "DVDMaker.exe" );
		if( dvdVer1 && version_is_less( version: dvdVer1, test_version: "6.0.6002.19725" ) ){
			Vulnerable_range = "Less than 6.0.6002.19725";
			VULN2 = TRUE;
		}
		else {
			if(dvdVer1 && version_in_range( version: dvdVer1, test_version: "6.0.6002.24000", test_version2: "6.0.6002.24047" )){
				Vulnerable_range = "6.0.6002.24000 - 6.0.6002.24047";
				VULN2 = TRUE;
			}
		}
	}
}
if( VULN1 ){
	report = "File checked:     " + filepath + "\\DVDMaker.exe" + "\n" + "File version:     " + dvdVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
else {
	if(VULN2){
		report = "File checked:     " + file1path + "\\DVDMaker.exe" + "\n" + "File version:     " + dvdVer1 + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

