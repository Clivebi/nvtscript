if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814968" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_cve_id( "CVE-2019-0953" );
	script_bugtraq_id( 108211 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-15 11:10:54 +0530 (Wed, 15 May 2019)" );
	script_name( "Microsoft Word Remote Code Execution Vulnerability (KB4464536)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4464536" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists in Microsoft Word software
  when it fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the currently logged-in user.
  Failed exploit attempts will likely result in denial of service conditions." );
	script_tag( name: "affected", value: "Microsoft Word 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4464536" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(version_in_range( version: exeVer, test_version: "16.0", test_version2: "16.0.4849.0999" )){
	report = report_fixed_ver( file_checked: exePath + "winword.exe", file_version: exeVer, vulnerable_range: "16.0 - 16.0.4849.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

