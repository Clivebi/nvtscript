if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811454" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2017-8557" );
	script_bugtraq_id( 99398 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-26 17:57:00 +0000 (Tue, 26 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-07-12 09:53:11 +0530 (Wed, 12 Jul 2017)" );
	script_name( "Microsoft Windows System Information Console Information Disclosure Vulnerability (KB4025398)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4025398" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in the Windows
  System Information Console when it improperly parses XML input containing a
  reference to an external entity." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to read arbitrary files via an XML external entity (XXE) declaration." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4025398" );
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
fileVer = fetch_file_version( sysPath: sysPath, file_name: "msinfo32.exe" );
if(!fileVer){
	exit( 0 );
}
if( version_is_less( version: fileVer, test_version: "6.0.6002.19810" ) ){
	Vulnerable_range = "Less than 6.0.6002.19810";
	VULN = TRUE;
}
else {
	if(version_in_range( version: fileVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.24129" )){
		Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24129";
		VULN = TRUE;
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\msinfo32.exe" + "\n" + "File version:     " + fileVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

