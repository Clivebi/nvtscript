if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812085" );
	script_version( "2020-06-04T12:11:49+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-04 12:11:49 +0000 (Thu, 04 Jun 2020)" );
	script_tag( name: "creation_date", value: "2017-11-15 07:15:57 +0530 (Wed, 15 Nov 2017)" );
	script_name( "Microsoft Word 2016 Defense in Depth Update (KB4011242)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011242" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as Microsoft has released
  an update for Microsoft Office that provides enhanced security as a
  defense-in-depth measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to
  compromise availability, integrity, and confidentiality of the system." );
	script_tag( name: "affected", value: "Microsoft Word 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011242" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( exeVer, "^16\\." ) && version_is_less( version: exeVer, test_version: "16.0.4615.1000" )){
	report = report_fixed_ver( file_checked: exePath + "winword.exe", file_version: exeVer, vulnerable_range: "16.0 - 16.0.4615.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

