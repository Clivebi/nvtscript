if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813123" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-1007" );
	script_bugtraq_id( 103640 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-11 09:07:39 +0530 (Wed, 11 Apr 2018)" );
	script_name( "Microsoft Office 2016 Information Disclosure Vulnerability (KB4011628)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011628" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as Microsoft Office improperly
  discloses the contents of its memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain access to potentially sensitive information and use the information to
  compromise the user's computer or data." );
	script_tag( name: "affected", value: "Microsoft Office 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011628" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
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
	key_list = make_list( "SOFTWARE\\Microsoft\\Office\\16.0\\Access\\InstallRoot" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Office\\16.0\\Access\\InstallRoot",
			 "SOFTWARE\\Microsoft\\Office\\16.0\\Access\\InstallRoot" );
	}
}
for key in key_list {
	comPath = registry_get_sz( key: key, item: "Path" );
	if(comPath){
		ortVer = fetch_file_version( sysPath: comPath, file_name: "Oart.dll" );
		if(ortVer && IsMatchRegexp( ortVer, "^16\\." )){
			if(version_is_less( version: ortVer, test_version: "16.0.4672.1000" )){
				report = report_fixed_ver( file_checked: comPath + "Oart.dll", file_version: ortVer, vulnerable_range: "16.0 - 16.0.4672.0999" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

