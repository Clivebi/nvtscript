if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812127" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-11-15 00:48:19 +0530 (Wed, 15 Nov 2017)" );
	script_name( "Microsoft SharePoint Server 2013 Service Pack 1 Word Automation Services Defense in Depth Update (KB4011245)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011245" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Microsoft has released an update for Microsoft
  Office that provides enhanced security as a defense-in-depth measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to compromise system's availability, integrity, and confidentiality." );
	script_tag( name: "affected", value: "Microsoft SharePoint Server 2013 Service Pack 1 Word Automation Services." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011245" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!infos = get_app_version_and_location( cpe: "cpe:/a:microsoft:sharepoint_server", exit_no_version: TRUE )){
	exit( 0 );
}
shareVer = infos["version"];
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( shareVer, "^(15\\.)" )){
	dllVer = fetch_file_version( sysPath: path, file_name: "\\15.0\\WebServices\\ConversionServices\\sword.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4981.0999" )){
			report = report_fixed_ver( file_checked: path + "\\15.0\\WebServices\\ConversionServices\\sword.dll", file_version: dllVer, vulnerable_range: "15.0 - 15.0.4981.0999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

