if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813277" );
	script_version( "2021-06-22T11:00:29+0000" );
	script_cve_id( "CVE-2018-8378", "CVE-2018-8382" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-15 10:30:29 +0530 (Wed, 15 Aug 2018)" );
	script_name( "Microsoft Excel Viewer 2007 Service Pack 3 Multiple Vulnerabilities (KB4022195)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4022195" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - When Microsoft Excel improperly discloses the contents of its memory.

  - When Microsoft Office software reads out of bound memory due to an
    uninitialized variable, which could disclose the contents of memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to view out of bound memory and use the information to compromise the users
  computer or data." );
	script_tag( name: "affected", value: "Microsoft Excel Viewer 2007 Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4022195" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/ComptPack/Version" );
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
	commonpath = registry_get_sz( key: key, item: "CommonFilesDir" );
	if(!commonpath){
		exit( 0 );
	}
	offPath = commonpath + "\\Microsoft Shared\\Office12";
	offexeVer = fetch_file_version( sysPath: offPath, file_name: "Mso.dll" );
	if(!offexeVer){
		continue;
	}
	if(version_in_range( version: offexeVer, test_version: "12.0", test_version2: "12.0.6802.4999" )){
		report = report_fixed_ver( file_checked: offPath + "\\Mso.dl", file_version: offexeVer, vulnerable_range: "12.0 - 12.0.6802.4999" );
		security_message( data: report );
		exit( 0 );
	}
}

