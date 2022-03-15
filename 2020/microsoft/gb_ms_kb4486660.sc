if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817449" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_cve_id( "CVE-2020-1218" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-16 18:42:00 +0000 (Wed, 16 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-09 11:21:42 +0530 (Wed, 09 Sep 2020)" );
	script_name( "Microsoft Word 2010 Service Pack 2 Remote Code Execution Vulnerability (KB448666)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB448666" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "A remote code execution vulnerability exists
  in Microsoft Word software when it fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute the code and compromise the user's computer or data." );
	script_tag( name: "affected", value: "Microsoft Word 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/448666" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
exeVer = get_kb_item( "SMB/Office/Word/Version" );
if(!exeVer){
	exit( 0 );
}
exePath = get_kb_item( "SMB/Office/Word/Install/Path" );
if(!exePath){
	exePath = "Unable to fetch the install path";
}
if(IsMatchRegexp( exeVer, "^14\\." ) && version_is_less( version: exeVer, test_version: "14.0.7258.5000" )){
	report = report_fixed_ver( file_checked: exePath + "winword.exe", file_version: exeVer, vulnerable_range: "14.0 - 14.0.7258.4999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

