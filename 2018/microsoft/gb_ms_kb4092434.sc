if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813293" );
	script_version( "2021-06-22T11:00:29+0000" );
	script_cve_id( "CVE-2018-8378" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-15 11:39:50 +0530 (Wed, 15 Aug 2018)" );
	script_name( "Microsoft Office Word Viewer Information Disclosure Vulnerability (KB4092434)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4092434" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Microsoft Office software
  reads out of bound memory due to an uninitialized variable, which could disclose
  the contents of memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to view out of bound memory." );
	script_tag( name: "affected", value: "Microsoft Office Word Viewer." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4092434" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
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
	propath = registry_get_sz( key: key, item: "CommonFilesDir" );
	if(propath){
		offPath = propath + "\\Microsoft Shared\\OFFICE11";
		exeVer = fetch_file_version( sysPath: offPath, file_name: "Mso.dll" );
		if(exeVer && IsMatchRegexp( exeVer, "^(11\\.)" )){
			if(version_is_less( version: exeVer, test_version: "11.0.8450.0" )){
				report = report_fixed_ver( file_checked: offPath + "\\Mso.dll", file_version: exeVer, vulnerable_range: "11.0 - 11.0.8449" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}

