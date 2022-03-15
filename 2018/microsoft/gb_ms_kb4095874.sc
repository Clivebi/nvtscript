if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813226" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-0765", "CVE-2018-1039" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-14 18:01:00 +0000 (Thu, 14 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-05-09 13:04:50 +0530 (Wed, 09 May 2018)" );
	script_name( "Microsoft .NET Framework Multiple Vulnerabilities (KB4095874)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Security Updates KB4095874." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - .NET Framework (and .NET Core) components do not completely validate
    certificates.

  - .NET, and .NET core, improperly process XML documents." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service against a .NET application and also
  to bypass cetain security restrictions." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 3.5.1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4095874" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
key2 = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\";
for item in registry_enum_keys( key: key2 ) {
	path = registry_get_sz( key: key2 + item, item: "All Assemblies In" );
	if(path){
		dllVer = fetch_file_version( sysPath: path, file_name: "system.identitymodel.dll" );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "3.0.4506.7082", test_version2: "3.0.4506.8788" )){
				report = report_fixed_ver( file_checked: path + "system.identitymodel.dll", file_version: dllVer, vulnerable_range: "3.0.4506.7082 - 3.0.4506.8788" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

