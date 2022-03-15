if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812239" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-11937", "CVE-2017-11940" );
	script_bugtraq_id( 102070, 102104 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-12-08 11:55:19 +0530 (Fri, 08 Dec 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Malware Protection Engine on Security Essentials Multiple Remote Code Execution Vulnerabilities" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Security Updates released for Microsoft Malware
  Protection Engine dated 12/06/2017" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist when the Microsoft
  Malware Protection Engine does not properly scan a specially crafted file,
  leading to memory corruption." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the security context of the LocalSystem account
  and take control of the system. An attacker could then:

  - install programs

  - view, change, or delete data

  - create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft Security Essentials." );
	script_tag( name: "solution", value: "Run the Windows Update to update the malware
  protection engine to the latest version available. Typically, no action is
  required as the built-in mechanism for the automatic detection and deployment
  of updates will apply the update itself." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11937" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11940" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Microsoft Antimalware";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
def_version = registry_get_sz( key: "SOFTWARE\\Microsoft\\Microsoft Antimalware\\Signature Updates", item: "EngineVersion" );
if(!def_version){
	exit( 0 );
}
if(version_is_less( version: def_version, test_version: "1.1.14405.2" )){
	report = report_fixed_ver( installed_version: def_version, fixed_version: "1.1.14405.2" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

