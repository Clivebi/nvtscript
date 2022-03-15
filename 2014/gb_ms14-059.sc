if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804778" );
	script_version( "2019-05-03T10:54:50+0000" );
	script_cve_id( "CVE-2014-4075" );
	script_bugtraq_id( 70352 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)" );
	script_tag( name: "creation_date", value: "2014-10-15 15:14:33 +0530 (Wed, 15 Oct 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ASP.NET MVC Security Feature Bypass Vulnerability (2990942)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS14-059." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Certain unspecified input is not properly
  sanitised in System.Web.Mvc.dll before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "ASP.NET MVC 2.0/3.0/4.0/5.0/5.1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/60971" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms14-059" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		if(ContainsString( item, "ASP.NET MVC" )){
			path = registry_get_sz( key: key + item + "\\Runtime", item: "InstallPath" );
			if(path && ContainsString( path, "Microsoft ASP.NET\\ASP.NET MVC" )){
				dllVer = fetch_file_version( sysPath: path + "Assemblies", file_name: "System.Web.Mvc.dll" );
				if(dllVer){
					if(version_in_range( version: dllVer, test_version: "2.0", test_version2: "2.0.60813.9" ) || version_in_range( version: dllVer, test_version: "3.0", test_version2: "3.0.50813.0" ) || version_in_range( version: dllVer, test_version: "4.0", test_version2: "4.0.40803.9" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
						exit( 0 );
					}
				}
			}
		}
	}
}

