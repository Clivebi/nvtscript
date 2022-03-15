if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806190" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-0012" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-01-13 11:57:20 +0530 (Wed, 13 Jan 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Visio Remote Code Execution Vulnerability (3124585)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-004" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Office software improperly handles objects
  in memory while parsing specially crafted Office files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and to
  perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Visio 2007

  - Microsoft Visio 2010

  - Microsoft Visio 2013

  - Microsoft Visio 2016" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114489" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114402" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114421" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-004" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms16-004" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\visio.exe", item: "Path" );
if(!sysPath){
	exit( 0 );
}
excelVer = fetch_file_version( sysPath: sysPath, file_name: "visio.exe" );
if(IsMatchRegexp( excelVer, "^(12|14|15|16)\\..*" )){
	if( IsMatchRegexp( excelVer, "^12" ) ){
		Vulnerable_range = "12 - 12.0.6741.4999";
	}
	else {
		if( IsMatchRegexp( excelVer, "^14" ) ){
			Vulnerable_range = "14 - 14.0.7165.4999";
		}
		else {
			if( IsMatchRegexp( excelVer, "^15" ) ){
				Vulnerable_range = "15 - 15.0.4787.0999";
			}
			else {
				if(IsMatchRegexp( excelVer, "^16" )){
					Vulnerable_range = "16 - 16.0.4324.0999";
				}
			}
		}
	}
	if(version_in_range( version: excelVer, test_version: "12.0", test_version2: "12.0.6741.4999" ) || version_in_range( version: excelVer, test_version: "14.0", test_version2: "14.0.7165.4999" ) || version_in_range( version: excelVer, test_version: "15.0", test_version2: "15.0.4787.0999" ) || version_in_range( version: excelVer, test_version: "16.0", test_version2: "16.0.4324.0999" )){
		report = "File checked:  " + sysPath + "visio.exe" + "\n" + "File version:     " + excelVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

