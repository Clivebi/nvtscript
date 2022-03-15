if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814651" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_cve_id( "CVE-2019-0537" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-14 17:52:03 +0530 (Mon, 14 Jan 2019)" );
	script_name( "Microsoft Visual Studio Multiple Information Disclosure Vulnerabilities (KB4476698, KB4476755)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Security Update January-2019." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Visual Studio improperly discloses arbitrary
  file contents if the victim opens a malicious .vscontent file." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to view arbitrary file contents from the computer where the victim launched
  Visual Studio." );
	script_tag( name: "affected", value: "- Microsoft Visual Studio 2010 Service Pack 1

  - Microsoft Visual Studio 2012 Update 5" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0537" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4476698" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4476755" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_visual_prdts_detect.sc" );
	script_mandatory_keys( "Microsoft/VisualStudio/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
vsVer = get_kb_item( "Microsoft/VisualStudio/Ver" );
if(!vsVer || !IsMatchRegexp( vsVer, "^1[01]\\." )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(IsMatchRegexp( vsVer, "^11\\." )){
	for key in key_list {
		for item in registry_enum_keys( key: key ) {
			upName = registry_get_sz( key: key + item, item: "DisplayName" );
			if(ContainsString( upName, "Visual Studio 2012 Update 5" )){
				if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Updates\\Microsoft Visual Studio 2012\\Update for Microsoft Visual Studio 2012 (KB4476755)" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Microsoft\\Updates\\Microsoft Visual Studio 2012\\Update for Microsoft Visual Studio 2012 (KB4476755)" )){
					report = report_fixed_ver( installed_version: "Visual Studio 2012 " + vsVer, fixed_version: "11.0.61239.0" );
					security_message( data: report );
					exit( 0 );
				}
			}
		}
	}
}
if(IsMatchRegexp( vsVer, "^10\\." )){
	if( ContainsString( os_arch, "x86" ) ){
		key_list_new = make_list( "SOFTWARE\\Microsoft\\DevDiv\\VS\\Servicing\\10.0\\" );
	}
	else {
		if(ContainsString( os_arch, "x64" )){
			key_list_new = make_list( "SOFTWARE\\Microsoft\\DevDiv\\VS\\Servicing\\10.0\\",
				 "SOFTWARE\\Wow6432Node\\Microsoft\\DevDiv\\VS\\Servicing\\10.0\\" );
		}
	}
	for key in key_list_new {
		servicepack = registry_get_dword( key: key, item: "SP" );
		if(servicepack == 1){
			for key in key_list {
				for item in registry_enum_keys( key: key ) {
					hotfixName = registry_get_sz( key: key + item, item: "DisplayName" );
					if(IsMatchRegexp( hotfixName, "^Hotfix for Microsoft Visual Studio 2010 .* - ENU \\(KB4476698\\)" )){
						flag = 1;
					}
				}
			}
			if(flag != 1){
				report = report_fixed_ver( installed_version: "Visual Studio 2010 SP1 " + vsVer, fixed_version: "10.0.40219.501" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

