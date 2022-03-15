if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813140" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-1037" );
	script_bugtraq_id( 103715 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-17 16:46:08 +0530 (Tue, 17 Apr 2018)" );
	script_name( "Microsoft Visual Studio 2015 Update 3 Information Disclosure Vulnerability (KB4087371)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4091346" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Visual Studio improperly
  discloses limited contents of uninitialized memory while compiling program
  database (PDB) files." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Microsoft Visual Studio 2015 Update 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4087371" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(!vsVer || !IsMatchRegexp( vsVer, "^14\\." )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\VisualStudio\\14.0" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\VisualStudio\\14.0",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\14.0" );
	}
}
for key in key_list {
	installPath = registry_get_sz( key: key, item: "InstallDir" );
	if(!installPath){
		continue;
	}
	dllVer = fetch_file_version( sysPath: installPath, file_name: "mspdbsrv.exe" );
	if(dllVer && IsMatchRegexp( dllVer, "^14\\.0" ) && version_is_less( version: dllVer, test_version: "14.0.24235.0" )){
		report = report_fixed_ver( file_checked: installPath + "mspdbsrv.exe", file_version: dllVer, vulnerable_range: "14.0 - 14.0.24234" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

