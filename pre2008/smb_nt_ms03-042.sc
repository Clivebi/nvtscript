if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11887" );
	script_version( "2020-06-09T11:16:08+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 11:16:08 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_xref( name: "IAVA", value: "2003-A-0029" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2003-0661" );
	script_name( "Buffer Overflow in Windows Troubleshooter ActiveX Control (826232)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Jeff Adams" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "A security vulnerability exists in the Microsoft Local Troubleshooter ActiveX control in
  Windows 2000." );
	script_tag( name: "insight", value: "The vulnerability exists because the ActiveX control (Tshoot.ocx) contains
  a buffer overflow.

  To exploit this vulnerability, the attacker would have to create a specially formed HTML based
  e-mail and send it to the user.

  Alternatively an attacker would have to host a malicious Web site that contained a Web page
  designed to exploit this vulnerability." );
	script_tag( name: "impact", value: "This flaw could allow an attacker to run code of their choice on a user's system." );
	script_tag( name: "affected", value: "Microsoft Windows 2000." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-042" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( win2k: 5 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "KB826232" ) > 0){
	security_message( port: 0 );
}

