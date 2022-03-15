if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807662" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0148" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-04-13 12:18:40 +0530 (Wed, 13 Apr 2016)" );
	script_name( "Microsoft .NET Framework Remote Code Execution Vulnerability (3148789)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-041." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to improper validation of
  input before Microsoft .NET Framework loads libraries." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to take complete control of an affected system." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 4.6 and 4.6.1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3143693" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-041" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
version = registry_get_sz( key: key, item: "Version" );
if(!version){
	exit( 0 );
}
if(IsMatchRegexp( version, "^4\\.6" )){
	dotPath = registry_get_sz( key: key, item: "InstallPath" );
	if(dotPath && ContainsString( dotPath, "Microsoft.NET" )){
		dllVer = fetch_file_version( sysPath: dotPath, file_name: "mscorlib.dll" );
		if(dllVer){
			if(( hotfix_check_sp( winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_is_less( version: dllVer, test_version: "4.6.1076.0" ) )){
				report = "File checked:     " + dotPath + "\\mscorlib.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "Less than 4.6.1076.0" + "\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}

