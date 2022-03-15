if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810269" );
	script_version( "2021-05-07T12:04:10+0000" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-07 12:04:10 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2017-01-12 18:49:43 +0530 (Thu, 12 Jan 2017)" );
	script_name( "Microsoft Identity Model Extensions Token Signing Verification Advisory (3214296)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "WMI/access_successful", "SMB/WindowsVersion" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/3214296.aspx" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft advisory (3214296)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to tokens signed with
  symmetric keys could be vulnerable to tampering. If a token signed with a
  symmetric key is used to verify the identity of a user, and the app makes
  decisions based on the verified identity of that user, then the app could
  make incorrect decisions." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to cause elevation of privilege." );
	script_tag( name: "affected", value: "- Microsoft.IdentityModel.Tokens package
  version 5.1.0 on Microsoft .NET Core or .NET Framework project" );
	script_tag( name: "solution", value: "Upgrade to Microsoft.IdentityModel.Tokens
  version 5.1.1 or later. Please see the references for more info." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
infos = kb_smb_wmi_connectinfo();
if(!infos){
	exit( 0 );
}
handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
if(!handle){
	exit( 0 );
}
fileList = wmi_file_fileversion( handle: handle, fileName: "Microsoft.IdentityModel.Tokens", fileExtn: "dll", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
for filePath in keys( fileList ) {
	vers = fileList[filePath];
	if(vers && version = eregmatch( string: vers, pattern: "^([0-9.]+)" )){
		if(version_is_equal( version: version[1], test_version: "5.1.0" )){
			report = report_fixed_ver( file_version: version[1], file_checked: filePath, fixed_version: "5.1.1" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

