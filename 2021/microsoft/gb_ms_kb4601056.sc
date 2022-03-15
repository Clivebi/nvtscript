if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817663" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_cve_id( "CVE-2021-24111" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-09 14:38:00 +0000 (Tue, 09 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-02-10 08:26:42 +0530 (Wed, 10 Feb 2021)" );
	script_name( "Microsoft .NET Framework Denial of Service Vulnerability (KB4601056)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4601056" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when the .NET
  Framework improperly handles data." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct a denial of service attack." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 4.8 on Microsoft Windows 10 version 1909." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4601056" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
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
if(IsMatchRegexp( edgeVer, "^11\\.0\\.18362" )){
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
						dllVer = fetch_file_version( sysPath: dotPath, file_name: "System.web.dll" );
						if(dllVer){
							if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.4329" )){
								vulnerable_range = "4.8 - 4.8.4329";
								break;
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
					dllVer = fetch_file_version( sysPath: dotPath, file_name: "System.web.dll" );
					if(dllVer){
						if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.4329" )){
							vulnerable_range = "4.8 - 4.8.4329";
							break;
						}
					}
				}
			}
		}
		if(( !vulnerable_range ) && ContainsString( key, "NET Framework Setup" )){
			dotPath = registry_get_sz( key: key, item: "InstallPath" );
			if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
				dllVer = fetch_file_version( sysPath: dotPath, file_name: "System.web.dll" );
				if(dllVer){
					if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.4329" )){
						vulnerable_range = "4.8 - 4.8.4329";
					}
				}
			}
		}
		if(vulnerable_range){
			report = report_fixed_ver( file_checked: dotPath + "System.web.dll", file_version: dllVer, vulnerable_range: vulnerable_range );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

