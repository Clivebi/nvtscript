if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811121" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_cve_id( "CVE-2017-0290" );
	script_bugtraq_id( 98330 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 22:03:00 +0000 (Wed, 08 May 2019)" );
	script_tag( name: "creation_date", value: "2017-05-17 10:28:37 +0530 (Wed, 17 May 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Security Essentials Remote Code Execution Vulnerability (KB4022344)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4022344." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the Microsoft Malware
  Protection Engine does not properly scan a specially crafted file leading to
  memory corruption." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the security context of the LocalSystem account and
  take control of the system. An attacker could then install programs. View, change,
  or delete data, or create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft Security Essentials." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/2510781" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/4022344" );
	script_xref( name: "URL", value: "https://bugs.chromium.org/p/project-zero/issues/detail?id=1252" );
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
key = "SOFTWARE\\Microsoft\\Microsoft Antimalware";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
def_version = registry_get_sz( key: "SOFTWARE\\Microsoft\\Microsoft Antimalware\\Signature Updates", item: "EngineVersion" );
if(!def_version){
	exit( 0 );
}
if(version_is_less( version: def_version, test_version: "1.1.13704.0" )){
	report = "Installed version : " + def_version + "\n" + "Vulnerable range: Less than 1.1.13704.0";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

