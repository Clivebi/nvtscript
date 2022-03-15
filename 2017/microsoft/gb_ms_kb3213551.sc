if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811788" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_cve_id( "CVE-2017-8744" );
	script_bugtraq_id( 100748 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-10-04 13:06:13 +0530 (Wed, 04 Oct 2017)" );
	script_name( "Microsoft Office 2016 Remote Code Execution Vulnerability (KB3213551)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3213551" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in Microsoft
  Office software when it fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability could use a specially crafted file
  to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office version 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3213551" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer || !IsMatchRegexp( officeVer, "^16\\." )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Office\\16.0\\Common\\FilesPaths\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Office\\16.0\\Common\\FilesPaths\\",
			 "SOFTWARE\\Microsoft\\Office\\16.0\\Common\\FilesPaths\\" );
	}
}
for key in key_list {
	filePath = registry_get_sz( key: key, item: "office.odf" );
	if(filePath){
		offPath = eregmatch( pattern: ".*Microsoft Shared\\\\", string: filePath );
		if(!offPath){
			exit( 0 );
		}
		offPath = offPath[0] + "TEXTCONV";
		offdllVer = fetch_file_version( sysPath: offPath, file_name: "wpft532.cnv" );
		if(!offdllVer){
			continue;
		}
		if(IsMatchRegexp( offdllVer, "^2012\\.1600\\." ) && version_is_less( version: offdllVer, test_version: "2012.1600.8326.2107" )){
			report = "File checked:     " + offPath + "\\wpft532.cnv" + "\n" + "File version:     " + offdllVer + "\n" + "Vulnerable range: " + "2012.1600.0.0 - 2012.1600.8326.2106" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

