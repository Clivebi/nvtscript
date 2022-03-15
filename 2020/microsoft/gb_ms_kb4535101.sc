if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815898" );
	script_version( "2021-08-12T06:00:50+0000" );
	script_cve_id( "CVE-2020-0646", "CVE-2020-0605", "CVE-2020-0606" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 06:00:50 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-26 17:15:00 +0000 (Thu, 26 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-01-15 10:11:12 +0530 (Wed, 15 Jan 2020)" );
	script_name( "Microsoft .NET Framework Multiple RCE Vulnerabilities (KB4535101" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4535101" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Microsoft .NET Framework fails to check the source markup of a file.

  - Microsoft .NET Framework fails to validate input properly." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user. If the current user
  is logged on with administrative user rights, an attacker could take control of
  the affected system." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 3.5, 4.7.2 and 4.8 on Microsoft Windows 10 version 1809 and Microsoft Windows Server 2019." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4535101" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1, win2019: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
edgeVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(!edgeVer){
	exit( 0 );
}
if(IsMatchRegexp( edgeVer, "^11\\.0\\.17763" )){
	if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\.NETFramework" )){
		if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\ASP.NET" )){
			if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\" )){
				exit( 0 );
			}
		}
	}
	key_list = make_list( "SOFTWARE\\Microsoft\\.NETFramework\\",
		 "SOFTWARE\\Microsoft\\ASP.NET\\",
		 "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\" );
	for key in key_list {
		if(ContainsString( key, ".NETFramework" )){
			for item in registry_enum_keys( key: key ) {
				NetPath = registry_get_sz( key: key + item, item: "InstallRoot" );
				if(NetPath && ContainsString( NetPath, "\\Microsoft.NET\\Framework" )){
					for item in registry_enum_keys( key: key ) {
						dotPath = NetPath + item;
						dllVer = fetch_file_version( sysPath: dotPath, file_name: "System.workflow.runtime.dll" );
						if(dllVer){
							if( version_in_range( version: dllVer, test_version: "3.0", test_version2: "3.0.4203.9042" ) ){
								vulnerable_range = "3.0 - 3.0.4203.9042";
								break;
							}
							else {
								if( version_in_range( version: dllVer, test_version: "4.7", test_version2: "4.7.3569" ) ){
									vulnerable_range = "4.7 - 4.7.3569";
									break;
								}
								else {
									if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.4109" )){
										vulnerable_range = "4.8 - 4.8.4109";
										break;
									}
								}
							}
						}
					}
				}
			}
		}
		if(( !vulnerable_range ) && ContainsString( key, "ASP.NET" )){
			for item in registry_enum_keys( key: key ) {
				dotPath = registry_get_sz( key: key + item, item: "Path" );
				if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
					dllVer = fetch_file_version( sysPath: dotPath, file_name: "System.workflow.runtime.dll" );
					if(dllVer){
						if( version_in_range( version: dllVer, test_version: "3.0", test_version2: "3.0.4203.9042" ) ){
							vulnerable_range = "3.0 - 3.0.4203.9042";
							break;
						}
						else {
							if( version_in_range( version: dllVer, test_version: "4.7", test_version2: "4.7.3569" ) ){
								vulnerable_range = "4.7 - 4.7.3569";
								break;
							}
							else {
								if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.4109" )){
									vulnerable_range = "4.8 - 4.8.4109";
									break;
								}
							}
						}
					}
				}
			}
		}
		if(( !vulnerable_range ) && ContainsString( key, "NET Framework Setup" )){
			dotPath = registry_get_sz( key: key, item: "InstallPath" );
			if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
				dllVer = fetch_file_version( sysPath: dotPath, file_name: "System.workflow.runtime.dll" );
				if(dllVer){
					if( version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.4109" ) ){
						vulnerable_range = "4.8 - 4.8.4109";
					}
					else {
						if(version_in_range( version: dllVer, test_version: "4.7", test_version2: "4.7.3569" )){
							vulnerable_range = "4.7 - 4.7.3569";
						}
					}
				}
			}
		}
		if(vulnerable_range){
			report = report_fixed_ver( file_checked: dotPath + "System.workflow.runtime.dll", file_version: dllVer, vulnerable_range: vulnerable_range );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );
