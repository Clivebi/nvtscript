if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812132" );
	script_version( "2020-06-04T12:11:49+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-04 12:11:49 +0000 (Thu, 04 Jun 2020)" );
	script_tag( name: "creation_date", value: "2017-11-15 08:04:08 +0530 (Wed, 15 Nov 2017)" );
	script_name( "Microsoft Office Word Viewer Defense in Depth Update (KB4011264)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011264" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Microsoft has released an update for Microsoft
  Office that provides enhanced security as a defense-in-depth measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to
  compromise availability, integrity, and confidentiality of the system." );
	script_tag( name: "affected", value: "Microsoft Office Word Viewer." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011264" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
if(!wordviewVer){
	exit( 0 );
}
wordviewPath = get_kb_item( "SMB/Office/WordView/Install/Path" );
if(!wordviewPath){
	wordviewPath = "Unable to fetch the install path";
}
if(IsMatchRegexp( wordviewVer, "^11\\." ) && version_is_less( version: wordviewVer, test_version: "11.0.8445" )){
	report = report_fixed_ver( file_checked: wordviewPath + "wordview.exe", file_version: wordviewVer, vulnerable_range: "11.0 - 11.0.8444" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

