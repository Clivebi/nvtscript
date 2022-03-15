if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814745" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_cve_id( "CVE-2019-0657", "CVE-2019-0613" );
	script_bugtraq_id( 106890, 106872 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-06 16:03:00 +0000 (Wed, 06 Mar 2019)" );
	script_tag( name: "creation_date", value: "2019-02-13 11:45:21 +0530 (Wed, 13 Feb 2019)" );
	script_name( "Microsoft .NET Framework Multiple Vulnerabilities (KB4483459)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4483459" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in .NET Framework when the software fails to check the source
    markup of a file.

  - An error in certain .Net Framework API's in the way they parse URL's." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass security logic intended to ensure that a user-provided URL belonged
  to a specific hostname or a subdomain of that hostname and run arbitrary code
  in the context of the current user." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 3.5 on Microsoft Windows 8.1

  - Microsoft Windows Server 2012 R2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4483459" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) <= 0){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\.NETFramework" )){
	if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\ASP.NET" )){
		exit( 0 );
	}
}
key_list = make_list( "SOFTWARE\\Microsoft\\.NETFramework\\",
	 "SOFTWARE\\Microsoft\\ASP.NET\\" );
for key in key_list {
	if(ContainsString( key, ".NETFramework" )){
		for item in registry_enum_keys( key: key ) {
			NetPath = registry_get_sz( key: key + item, item: "InstallRoot" );
			if(NetPath && ContainsString( NetPath, "\\Microsoft.NET\\Framework" )){
				for item in registry_enum_keys( key: key ) {
					dotPath = NetPath + item;
					dllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
					if(dllVer){
						if(version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8802" )){
							VULN = TRUE;
							break;
						}
					}
				}
			}
		}
	}
	if(( !VULN ) && ContainsString( key, "ASP.NET" )){
		for item in registry_enum_keys( key: key ) {
			dotPath = registry_get_sz( key: key + item, item: "Path" );
			if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
				dllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
				if(dllVer){
					if(version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8802" )){
						VULN = TRUE;
						break;
					}
				}
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( file_checked: dotPath + "\\system.dll", file_version: dllVer, vulnerable_range: "2.0.50727.5700 - 2.0.50727.8802" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

