if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806109" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2015-2545" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-09-09 10:11:44 +0530 (Wed, 09 Sep 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Suite Remote Code Execution Vulnerabilities (3089664)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS15-099." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A remote code execution exists in Microsoft Office that could be exploited when
  a user opens a file containing a malformed graphics image or when a user inserts
  a malformed graphics image into an Office file." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially
  execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2010 Service Pack 2 and prior

  - Microsoft Office 2013 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3089664" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-099" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_office_detection_900025.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
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
if(IsMatchRegexp( offVer, "^(12|14|15)\\..*" )){
	filePath = path + "\\Microsoft Shared\\TextConv";
	fileVer = fetch_file_version( sysPath: filePath, file_name: "Wpft532.cnv" );
	if(fileVer){
		if( IsMatchRegexp( fileVer, "^2006" ) ){
			Vulnerable_range = "2006 - 2006.1200.6722.4999";
		}
		else {
			if( IsMatchRegexp( fileVer, "^2010" ) ){
				Vulnerable_range = "2010 - 2010.1400.4730.1009";
			}
			else {
				if(IsMatchRegexp( fileVer, "^2012" )){
					Vulnerable_range = "2012 - 2012.1500.4727.0009";
				}
			}
		}
		if(version_in_range( version: fileVer, test_version: "2012", test_version2: "2012.1500.4727.0999" ) || version_in_range( version: fileVer, test_version: "2010", test_version2: "2010.1400.4730.1009" ) || version_in_range( version: fileVer, test_version: "2006", test_version2: "2006.1200.6722.4999" )){
			VULN = TRUE;
		}
		if(VULN){
			report = "File checked:     " + filePath + "Wpft532.cnv" + "\n" + "File version:     " + fileVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}

