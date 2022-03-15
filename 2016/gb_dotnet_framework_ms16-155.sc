if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809760" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-7270" );
	script_bugtraq_id( 94741 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-12-14 15:04:05 +0530 (Wed, 14 Dec 2016)" );
	script_name( "Microsoft .NET Framework Information Disclosure Vulnerability (3205640)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-155." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists as .NET Framework improperly uses
  a developer-supplied key. When this key is misused, it is also possible for
  access to data to be temporarily lost." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 4.6.2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3204805" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3204801" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3204802" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3206632" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms16-155" );
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
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1, win2016: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Client\\";
if(registry_key_exists( key: key )){
	pathv46 = registry_get_sz( key: key, item: "InstallPath" );
	if(pathv46){
		dllv46 = fetch_file_version( sysPath: pathv46, file_name: "system.data.dll" );
		if(dllv46){
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win2012: 1, win8_1x64: 1, win2012R2: 1, win8_1: 1 ) > 0){
				if(version_in_range( version: dllv46, test_version: "4.6", test_version2: "4.6.1635" )){
					report = "File checked:     " + pathv46 + "system.data.dll" + "\n" + "File version:     " + dllv46 + "\n" + "Vulnerable range: " + "4.6 - 4.6.1635" + "\n";
					security_message( data: report );
					exit( 0 );
				}
			}
		}
	}
}
if(hotfix_check_sp( win10: 1, win10x64: 1, win2016: 1 ) > 0){
	edgeVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
	if(!edgeVer){
		exit( 0 );
	}
	if(edgeVer && version_in_range( version: edgeVer, test_version: "11.0.14393.0", test_version2: "11.0.14393.575" )){
		report = "File checked:     " + sysPath + "\\edgehtml.dll" + "\n" + "File version:     " + edgeVer + "\n" + "Vulnerable range: 11.0.14393.0 - 11.0.14393.575" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

