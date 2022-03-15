if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813763" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-8360" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-15 14:03:00 +0000 (Mon, 15 Oct 2018)" );
	script_tag( name: "creation_date", value: "2018-08-15 10:51:10 +0530 (Wed, 15 Aug 2018)" );
	script_name( "Microsoft .NET Framework Information Disclosure Vulnerability (KB4344149)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4344149" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when .NET Framework is used
  in high-load/high-density network connections where content from one stream
  can blend into another stream." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to access information in multi-tenant environments." );
	script_tag( name: "affected", value: ".NET Framework 4.5.2 for Windows 7 SP1,
  Server 2008 R2 SP1, and Server 2008 SP2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4344149" );
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
if(hotfix_check_sp( win2008: 3, win2008x64: 3, win7: 2, win7x64: 2, win2008r2: 2 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	dotPath = registry_get_sz( key: key + item, item: "Path" );
	if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
		if(!dllVer || !IsMatchRegexp( dllVer, "^4\\." )){
			continue;
		}
		if(version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36459" )){
			report = report_fixed_ver( file_checked: dotPath + "\\system.dll", file_version: dllVer, vulnerable_range: "4.0.30319.30000 - 4.0.30319.36459" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

