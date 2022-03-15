if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817300" );
	script_version( "2021-08-11T12:01:46+0000" );
	script_cve_id( "CVE-2020-1425", "CVE-2020-1457" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-29 13:50:00 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-02 17:39:49 +0530 (Thu, 02 Jul 2020)" );
	script_name( "Microsoft Windows Codecs Library Multiple Remote Code Execution Vulnerabilities" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft updates for Windows Codecs Library." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors
  in the way that Microsoft Windows codecs library handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1709 for 32-bit Systems

  - Microsoft Windows 10 Version 1709 for x64-based Systems

  - Microsoft Windows 10 Version 1803 for 32-bit Systems

  - Microsoft Windows 10 Version 1803 for x64-based Systems

  - Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows 10 Version 1903 for 32-bit Systems

  - Microsoft Windows 10 Version 1903 for x64-based Systems

  - Microsoft Windows 10 Version 1909 for 32-bit Systems

  - Microsoft Windows 10 Version 1909 for x64-based Systems

  - Microsoft Windows 10 Version 2004 for 32-bit Systems

  - Microsoft Windows 10 Version 2004 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates and will be
  automatically installed. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1457" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1425" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
edgeVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(!edgeVer){
	exit( 0 );
}
gdiVer = fetch_file_version( sysPath: sysPath, file_name: "Gdiplus.dll" );
if(!gdiVer){
	exit( 0 );
}
if(IsMatchRegexp( edgeVer, "^11\\.0\\.17134" ) || IsMatchRegexp( edgeVer, "^11\\.0\\.17763" ) || IsMatchRegexp( edgeVer, "^11\\.0\\.18362" ) || IsMatchRegexp( edgeVer, "^11\\.0\\.16299" ) || IsMatchRegexp( gdiVer, "^10\\.0\\.19041" )){
	os_arch = get_kb_item( "SMB/Windows/Arch" );
	if(!os_arch){
		exit( 0 );
	}
	if( ContainsString( os_arch, "x86" ) ){
		key_list = make_list( "SOFTWARE\\Microsoft\\SecurityManager\\CapAuthz\\ApplicationsEx\\" );
	}
	else {
		if(ContainsString( os_arch, "x64" )){
			key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\SecurityManager\\CapAuthz\\ApplicationsEx\\",
				 "SOFTWARE\\Microsoft\\SecurityManager\\CapAuthz\\ApplicationsEx\\" );
		}
	}
	maxVer = "";
	for key in key_list {
		for item in registry_enum_keys( key: key ) {
			if(ContainsString( item, "HEVCVideoExtension" )){
				version = eregmatch( pattern: "HEVCVideoExtension_([0-9.]+)_", string: item );
				if(!isnull( version[1] )){
					if( isnull( maxVer ) ){
						maxVer = version[1];
					}
					else {
						if( version_is_greater( version: version[1], test_version: maxVer ) ){
							maxVer = version[1];
						}
						else {
							continue;
						}
					}
				}
			}
		}
	}
	if(!isnull( maxVer ) && IsMatchRegexp( maxVer, "[0-9.]+" )){
		if(version_is_less( version: maxVer, test_version: "1.0.31822.0" )){
			report = report_fixed_ver( installed_version: maxVer, fixed_version: "1.0.31822.0", vulnerable_range: "Less than 1.0.31822.0" );
			security_message( data: report );
			exit( 0 );
		}
	}
}

