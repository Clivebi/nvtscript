if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813179" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-8155" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-05 19:38:00 +0000 (Tue, 05 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-05-09 11:17:23 +0530 (Wed, 09 May 2018)" );
	script_name( "Microsoft SharePoint Foundation 2013 Service Pack 1 Elevation of Privilege Vulnerability (KB4018398)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4018398" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Microsoft SharePoint
  Server does not properly sanitize a specially crafted web request to an
  affected SharePoint server." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain elevated privileges on affected system." );
	script_tag( name: "affected", value: "Microsoft SharePoint Foundation 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4018398" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_mandatory_keys( "MS/SharePoint/Foundation/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: "cpe:/a:microsoft:sharepoint_foundation", exit_no_version: TRUE )){
	exit( 0 );
}
shareVer = infos["version"];
if(!IsMatchRegexp( shareVer, "^15\\." )){
	exit( 0 );
}
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
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
	path = registry_get_sz( key: key, item: "CommonFilesDir" );
	if(path){
		path = path + "\\microsoft shared\\SERVER15\\Server Setup Controller";
		dllVer = fetch_file_version( sysPath: path, file_name: "Wsssetup.dll" );
		if(!dllVer){
			continue;
		}
		if(IsMatchRegexp( dllVer, "^15\\." )){
			if(version_is_less( version: dllVer, test_version: "15.0.5031.1000" )){
				report = report_fixed_ver( file_checked: path + "\\Wsssetup.dll", file_version: dllVer, vulnerable_range: " 15 - 15.0.5031.0999" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

