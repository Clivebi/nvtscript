if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11215" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6367 );
	script_cve_id( "CVE-2002-1256" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Flaw in SMB Signing Could Enable Group Policy to be Modified (329170)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 SECNAP Network Security" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "The SMB signing capability in the Server Message Block
  protocol in Microsoft Windows 2000 and Windows XP allows attackers to disable the digital
  signing settings in an SMB session to force the data to be sent unsigned, then inject data
  into the session without detection, e.g. by modifying group policy information sent from a
  domain controller." );
	script_tag( name: "affected", value: "- Microsoft Windows 2000

  - Microsoft Windows XP" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-070" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( xp: 2 ) == 0 && hotfix_missing( name: "896422" ) == 0){
	exit( 0 );
}
if(hotfix_check_sp( nt: 7, win2k: 4, xp: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "Q329170" ) > 0){
	security_message( port: 0 );
}

