if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11147" );
	script_version( "2020-06-09T11:16:08+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 11:16:08 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4387, 5874 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0693", "CVE-2002-0694" );
	script_name( "Unchecked Buffer in Windows Help(Q323255)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 SECNAP Network Security, LLC" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "An unchecked buffer in Windows help could allow an attacker to
  could gain control over user's system." );
	script_tag( name: "affected", value: "- Microsoft Windows 98

  - Microsoft Windows 98 (Second Edition)

  - Microsoft Windows (Millennium Edition)

  - Microsoft Windows NT 4.0

  - Microsoft Windows NT 4.0 (Terminal Server Edition)

  - Microsoft Windows 2000

  - Microsoft Windows XP" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-055" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( nt: 7, win2k: 4, xp: 1 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "Q323255" ) > 0){
	security_message( port: 0 );
}

