if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812876" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-0765", "CVE-2018-1039" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-14 18:01:00 +0000 (Thu, 14 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-05-09 13:39:10 +0530 (Wed, 09 May 2018)" );
	script_name( "Microsoft .NET Framework Multiple Vulnerabilities (KB4095873)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4095873" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - When .NET and .NET Core improperly process XML documents and

  - In .Net Framework which could allow an attacker to bypass
    Device Guard." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to cause a denial of service and circumvent a User Mode Code
  Integrity (UMCI) policy on the machine." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 3.0 Service Pack 2 on Microsoft Windows Server 2008

  - Microsoft .NET Framework 2.0 Service Pack 2 on Microsoft Windows Server 2008" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4095873" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2008: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "mscorlib.dll" );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8783" )){
				report = report_fixed_ver( file_checked: path + "\\mscorlib.dll", file_version: dllVer, vulnerable_range: "2.0.50727.5700 - 2.0.50727.8783" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

