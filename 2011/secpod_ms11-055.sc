if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902455" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2010-3148" );
	script_bugtraq_id( 42681 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)" );
	script_name( "Microsoft Visio Remote Code Execution Vulnerability (2560847)" );
	script_tag( name: "summary", value: "This host is missing an important
  security update according to Microsoft Bulletin MS11-055." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the way that Microsoft
  Office Visio loads external libraries, when handling specially crafted Visio files." );
	script_tag( name: "impact", value: "Successful exploitation could allow
  users to execute arbitrary code via a specially crafted visio file." );
	script_tag( name: "affected", value: "Microsoft Office Visio 2003 SP3 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2493523" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-055" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
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
ovPath = registry_get_sz( item: "Path", key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\visio.exe" );
if(!ovPath){
	exit( 0 );
}
offPath = ovPath - "\\Visio11" + "OFFICE11";
dllVer = fetch_file_version( sysPath: offPath, file_name: "Omfc.dll" );
if(!dllVer){
	exit( 0 );
}
if(version_in_range( version: dllVer, test_version: "11.0", test_version2: "11.0.8331.0" )){
	report = "File checked:     " + offPath + "Omfc.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: 11.0 - 11.0.8331.0 \n";
	security_message( data: report );
	exit( 0 );
}

