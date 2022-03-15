if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811324" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_cve_id( "CVE-2017-8759" );
	script_bugtraq_id( 100742 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-14 02:29:00 +0000 (Sun, 14 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-09-13 15:08:36 +0530 (Wed, 13 Sep 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft .NET Framework Remote Code Execution Vulnerability (KB4040977)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4040977" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A remote code execution vulnerability exists
  when Microsoft .NET Framework processes untrusted input. An attacker who
  successfully exploited this vulnerability in software using the .NET framework
  could take control of an affected system." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute code." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 4.5.2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4040977" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	dotpath = registry_get_sz( key: key + item, item: "Path" );
	if(dotpath && ContainsString( dotpath, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: dotpath, file_name: "System.dll" );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36414" )){
				report = "File checked:     " + dotpath + "\\system.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: 4.0.30319.36000 - 4.0.30319.36414" + "\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}

