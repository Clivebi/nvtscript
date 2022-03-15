if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812703" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-0764", "CVE-2018-0786" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-01-10 10:03:51 +0530 (Wed, 10 Jan 2018)" );
	script_name( "Microsoft .NET Framework DoS And Security Feature Bypass Vulnerability (KB4055000)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Security Updates KB4055000." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - .NET Framework (and .NET Core) components do not completely validate
    certificates.

  - .NET, and .NET core, improperly process XML documents." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service against a .NET application and also
  to bypass cetain security restrictions." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 4.6

  - Microsoft .NET Framework 4.6.1

  - Microsoft .NET Framework 4.6.2

  - Microsoft .NET Framework 4.7" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4055000" );
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
if(hotfix_check_sp( win2012: 1 ) <= 0){
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
			if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.7.2611" )){
				report = "File checked:     " + path + "\\system.identitymodel.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: 4.6 - 4.7.2611\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

