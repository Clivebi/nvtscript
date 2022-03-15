if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807842" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2016-3235" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-06-15 12:09:59 +0530 (Wed, 15 Jun 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Visio Remote Code Execution Vulnerability (3163610)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-070" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error within Office
  software when Windows improperly validates input before loading libraries." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and to
  perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Visio 2007

  - Microsoft Visio 2010

  - Microsoft Visio 2013

  - Microsoft Visio 2016" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114872" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114740" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115020" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115041" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-070" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\visio.exe", item: "Path" );
if(!sysPath){
	exit( 0 );
}
visioVer = fetch_file_version( sysPath: sysPath, file_name: "visio.exe" );
if(IsMatchRegexp( visioVer, "^(12|14|15|16)\\..*" )){
	if( IsMatchRegexp( visioVer, "^12" ) ){
		Vulnerable_range = "12 - 12.0.6749.4999";
	}
	else {
		if( IsMatchRegexp( visioVer, "^14" ) ){
			Vulnerable_range = "14 - 14.0.7170.4999";
		}
		else {
			if( IsMatchRegexp( visioVer, "^15" ) ){
				Vulnerable_range = "15 - 15.0.4831.0999";
			}
			else {
				if(IsMatchRegexp( visioVer, "^16" )){
					Vulnerable_range = "16 - 16.0.4390.0999";
				}
			}
		}
	}
	if(version_in_range( version: visioVer, test_version: "12.0", test_version2: "12.0.6749.4999" ) || version_in_range( version: visioVer, test_version: "14.0", test_version2: "14.0.7170.4999" ) || version_in_range( version: visioVer, test_version: "15.0", test_version2: "15.0.4831.0999" ) || version_in_range( version: visioVer, test_version: "16.0", test_version2: "16.0.4390.0999" )){
		report = "File checked:     " + sysPath + "visio.exe" + "\n" + "File version:     " + visioVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

