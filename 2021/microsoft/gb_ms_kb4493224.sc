if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817677" );
	script_version( "2021-08-25T14:01:09+0000" );
	script_cve_id( "CVE-2021-27056" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-23 14:33:00 +0000 (Tue, 23 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 08:24:35 +0530 (Wed, 10 Mar 2021)" );
	script_name( "Microsoft PowerPoint 2016 RCE Vulnerability (KB4493224" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4493224" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to presence of remote code
  execution flaws in Microsoft PowerPoint" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code." );
	script_tag( name: "affected", value: "Microsoft PowerPoint 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the
  references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4493224" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/PowerPnt/Version", "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
pptVer = get_kb_item( "SMB/Office/PowerPnt/Version" );
if(!pptVer){
	exit( 0 );
}
if(!os_arch = get_kb_item( "SMB/Windows/Arch" )){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
	}
}
for key in key_list {
	commonpath = registry_get_sz( key: key, item: "ProgramFilesDir" );
	if(!commonpath){
		continue;
	}
	offPath = commonpath + "\\Microsoft Office\\OFFICE16";
	exeVer = fetch_file_version( sysPath: offPath, file_name: "ppcore.dll" );
	if(!exeVer){
		exit( 0 );
	}
	if(IsMatchRegexp( exeVer, "^16\\." ) && version_is_less( version: exeVer, test_version: "16.0.5131.1000" )){
		report = report_fixed_ver( file_checked: offPath + "\\ppcore.dll", file_version: exeVer, vulnerable_range: "16.0 - 16.0.5131.0999" );
		security_message( data: report );
	}
}
exit( 99 );

