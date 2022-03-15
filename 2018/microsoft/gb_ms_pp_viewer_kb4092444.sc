if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814253" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-8427", "CVE-2018-8432" );
	script_bugtraq_id( 105453, 105458 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-10 08:59:02 +0530 (Wed, 10 Oct 2018)" );
	script_name( "Microsoft PowerPoint Viewer 2007 Multiple Vulnerabilities (KB4092444)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4092444" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to an error in the
  way that Microsoft Graphics Components handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to execute arbitrary code and obtain
  information that could be useful for further exploitation." );
	script_tag( name: "affected", value: "Microsoft PowerPoint Viewer 2007." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4092444" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/PPView/Version" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
ppviewVer = get_kb_item( "SMB/Office/PPView/Version" );
if(!ppviewVer){
	exit( 0 );
}
if(IsMatchRegexp( ppviewVer, "^12" )){
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
			continue;
		}
		offPath = commonpath + "\\Microsoft Shared\\OFFICE12";
		msdllVer = fetch_file_version( sysPath: offPath, file_name: "Ogl.dll" );
		if(IsMatchRegexp( msdllVer, "^(12\\.)" ) && version_is_less( version: msdllVer, test_version: "12.0.6803.5000" )){
			report = report_fixed_ver( file_checked: offPath + "\\Ogl.dll", file_version: msdllVer, vulnerable_range: "12.0 - 12.0.6803.4999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

