if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900289" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)" );
	script_bugtraq_id( 48175 );
	script_cve_id( "CVE-2011-1264" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Active Directory Certificate Services Web Enrollment Elevation of Privilege Vulnerability (2518295)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2518295" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-051" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Active Directory Certificate Services,

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is caused by improper input validation of a request parameter on an
  Active Directory Certificate Services Web Enrollment site." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS11-051." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2003: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(registry_key_exists( key: "SOFTWARE\\Classes\\AppID\\certsrv.exe" ) && registry_key_exists( key: "SOFTWARE\\Classes\\CertificateAuthority.DB" )){
	if(hotfix_missing( name: "2518295" ) == 1){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

