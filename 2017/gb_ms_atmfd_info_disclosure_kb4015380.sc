if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810924" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-0192" );
	script_bugtraq_id( 97452 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-04-12 10:47:16 +0530 (Wed, 12 Apr 2017)" );
	script_name( "Microsoft Windows 'ATMFD.dll' Information Disclosure Vulnerability (KB4015380)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4015380." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Adobe Type Manager Font Driver
  (ATMFD.dll) fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system." );
	script_tag( name: "affected", value: "- Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-gb/help/4015380" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance" );
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
if(hotfix_check_sp( winVista: 3, win2008: 3, winVistax64: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
asVer = fetch_file_version( sysPath: sysPath, file_name: "Atmfd.dll" );
if(!asVer){
	exit( 0 );
}
if(version_is_less( version: asVer, test_version: "5.1.2.251" )){
	Vulnerable_range = "Less than 5.1.2.251";
	report = "File checked:     " + sysPath + "\\Atmfd.dll" + "\n" + "File version:     " + asVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

