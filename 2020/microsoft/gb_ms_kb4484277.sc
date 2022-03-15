if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816598" );
	script_version( "2021-08-12T03:01:00+0000" );
	script_cve_id( "CVE-2020-0850", "CVE-2020-0892", "CVE-2020-0852" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 03:01:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-04 14:14:00 +0000 (Mon, 04 May 2020)" );
	script_tag( name: "creation_date", value: "2020-03-11 10:10:57 +0000 (Wed, 11 Mar 2020)" );
	script_name( "Microsoft SharePoint Enterprise Server 2016 Multiple RCE Vulnerabilities (KB4484277)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4484277." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist when Microsoft Word
  software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  use a specially crafted file to perform actions in the security context of the
  current user." );
	script_tag( name: "affected", value: "Microsoft SharePoint Server 2019." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4484277" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_mandatory_keys( "MS/SharePoint/Server/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: "cpe:/a:microsoft:sharepoint_server" )){
	exit( 0 );
}
shareVer = infos["version"];
if(!IsMatchRegexp( shareVer, "^16\\." )){
	exit( 0 );
}
path = infos["location"];
if( !path || ContainsString( path, "Could not find the install location" ) ){
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
		path = registry_get_sz( key: key, item: "ProgramFilesDir" );
		if(path){
			path = path + "\\Microsoft Office Servers\\16.0\\WebServices\\ConversionServices\\1033";
			dllVer = fetch_file_version( sysPath: path, file_name: "msoserverintl.dll" );
			if(dllVer){
				break;
			}
		}
	}
}
else {
	path = path + "\\16.0\\WebServices\\ConversionServices\\1033";
	dllVer = fetch_file_version( sysPath: path, file_name: "msoserverintl.dll" );
}
if(IsMatchRegexp( dllVer, "^16\\.0\\." ) && version_in_range( version: dllVer, test_version: "16.0.10337.12109", test_version2: "16.0.10357.20003" )){
	report = report_fixed_ver( file_checked: path + "\\msoserverintl.dll", file_version: dllVer, vulnerable_range: "16.0.10337.12109 - 16.0.10357.20003" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

