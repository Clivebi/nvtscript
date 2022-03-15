if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811859" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-11816" );
	script_bugtraq_id( 101094 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-15 19:33:00 +0000 (Wed, 15 May 2019)" );
	script_tag( name: "creation_date", value: "2017-10-11 09:51:23 +0530 (Wed, 11 Oct 2017)" );
	script_name( "Windows GDI Information Disclosure Vulnerability (KB4042121)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4042121" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the way that the
  Windows Graphics Device Interface (GDI) handles objects in memory, allowing
  an attacker to retrieve information from a targeted system." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to retrieve information from a targeted system. By itself,
  the information disclosure does not allow arbitrary code execution. However,
  it could allow arbitrary code to be run if the attacker uses it in combination
  with another vulnerability." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4042121" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: sysPath, file_name: "gdi32.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.0.6002.24200" )){
	report = "File checked:     " + sysPath + "\\gdi32.dll" + "\n" + "File version:     " + fileVer + "\n" + "Vulnerable range: Less than 6.0.6002.24200\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

