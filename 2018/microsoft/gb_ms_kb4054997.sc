if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812627" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-0764", "CVE-2018-0786" );
	script_bugtraq_id( 102387, 102380 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-01-10 14:33:54 +0530 (Wed, 10 Jan 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft .NET Framework 3.5 Multiple Vulnerabilities (KB4054997)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4054997" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error when .NET, and .NET core, improperly process XML documents.

  - An error when Microsoft .NET Framework (and .NET Core) components do not
    completely validate certificates." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions and conduct a denial-of-service
  condition." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 3.5

  - Microsoft Windows Server 2012" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4054997" );
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
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "System.Xml.dll" );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8772" )){
				report = report_fixed_ver( file_checked: path + "\\system.xml.dll", file_version: dllVer, vulnerable_range: "2.0.50727.5700 - 2.0.50727.8772" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

