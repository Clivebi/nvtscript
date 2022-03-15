if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804450" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2014-1756", "CVE-2014-1808" );
	script_bugtraq_id( 67274, 67279 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2014-05-14 12:01:21 +0530 (Wed, 14 May 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft Office Remote Code Execution Vulnerabilities (2961037)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS14-023." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "- The flaw is due to the Grammar Checker feature for Chinese (Simplified)
  loading libraries in an insecure manner.

  - An error when handling a certain response can be exploited to gain knowledge
  of access tokens used for authentication of the current user." );
	script_tag( name: "affected", value: "- Microsoft Office 2007 Service Pack 3 (proofing tools)

  - Microsoft Office 2010 Service Pack 2 (proofing tools) and prior

  - Microsoft Office 2013 Service Pack 1 (proofing tools) and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute the arbitrary
  code." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2767772" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2878284" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2878316" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms14-023" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
offVer = get_kb_item( "MS/Office/Ver" );
if(!offVer){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
if(!path){
	exit( 0 );
}
if(IsMatchRegexp( offVer, "^15.*" )){
	filePath = path + "\\Microsoft Shared\\OFFICE15";
	fileVer = fetch_file_version( sysPath: filePath, file_name: "Msores.dll" );
	if(fileVer){
		if(version_in_range( version: fileVer, test_version: "15.0", test_version2: "15.0.4615.999" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( appName, "Microsoft Office Proofing" )){
		ptPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(ptPath){
			for offver in make_list( "OFFICE12",
				 "OFFICE14",
				 "OFFICE15" ) {
				for langPack in make_list( "1025",
					 "1030",
					 "1031",
					 "1033",
					 "3082",
					 "1040",
					 "1041",
					 "1042",
					 "1044",
					 "1046",
					 "1049",
					 "2052",
					 "1028" ) {
					ptPath1 = ptPath + offver + "\\PROOF\\" + langPack;
					exeVer = fetch_file_version( sysPath: ptPath1, file_name: "\\Msgr3en.dll" );
					if(exeVer){
						if(( ContainsString( ptPath1, "1025" ) || ContainsString( ptPath1, "1030" ) || ContainsString( ptPath1, "1040" ) || ContainsString( ptPath1, "1044" ) || ContainsString( ptPath1, "1046" ) || ContainsString( ptPath1, "1049" ) ) && ( ContainsString( ptPath1, "OFFICE15" ) )){
							if(version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.4615.999" )){
								security_message( port: 0, data: "The target host was found to be vulnerable" );
								exit( 0 );
							}
						}
						if(( ContainsString( ptPath1, "1033" ) || ContainsString( ptPath1, "3082" ) || ContainsString( ptPath1, "1041" ) || ContainsString( ptPath1, "1042" ) || ContainsString( ptPath1, "1028" ) ) && ( ContainsString( ptPath1, "OFFICE15" ) )){
							if(version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.4454.999" )){
								security_message( port: 0, data: "The target host was found to be vulnerable" );
								exit( 0 );
							}
						}
						if(ContainsString( ptPath1, "1031" ) && ContainsString( ptPath1, "OFFICE15" )){
							if(version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.4611.999" )){
								security_message( port: 0, data: "The target host was found to be vulnerable" );
								exit( 0 );
							}
						}
						if(ContainsString( ptPath1, "2052" ) && !ContainsString( ptPath1, "OFFICE12" )){
							if(version_in_range( version: exeVer, test_version: "3.0", test_version2: "3.0.1710.0" )){
								security_message( port: 0, data: "The target host was found to be vulnerable" );
								exit( 0 );
							}
						}
						if(ContainsString( ptPath1, "2052" ) && ContainsString( ptPath1, "OFFICE12" )){
							if(version_in_range( version: exeVer, test_version: "3.0", test_version2: "3.0.1711.1199" )){
								security_message( port: 0, data: "The target host was found to be vulnerable" );
								exit( 0 );
							}
						}
					}
				}
			}
		}
	}
}

