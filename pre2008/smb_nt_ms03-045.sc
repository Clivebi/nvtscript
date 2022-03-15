if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11885" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 8827 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2003-0659" );
	script_name( "Buffer Overrun in the ListBox and in the ComboBox (824141)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 Jeff Adams" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "A vulnerability exists because the ListBox control and the ComboBox control
  both call a function, which is located in the User32.dll file, that contains a buffer overrun." );
	script_tag( name: "impact", value: "An attacker who had the ability to log on to a system
  interactively could run a program that could send a specially-crafted Windows
  message to any applications that have implemented the ListBox control or the
  ComboBox control, causing the application to take any action an attacker
  specified. An attacker must have valid logon credentials to exploit the
  vulnerability. This vulnerability could not be exploited remotely." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-045" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 2, win2003: 1 ) <= 0){
	exit( 0 );
}
if(hotfix_check_sp( xp: 2, nt: 7 ) > 0){
	if(hotfix_missing( name: "840987" ) == 0){
		exit( 0 );
	}
}
if(hotfix_check_sp( win2k: 5 ) > 0){
	if(hotfix_missing( name: "840987" ) == 0){
		exit( 0 );
	}
	if(hotfix_missing( name: "841533" ) == 0){
		exit( 0 );
	}
	if(hotfix_missing( name: "890859" ) == 0){
		exit( 0 );
	}
}
if(hotfix_missing( name: "824141" ) > 0){
	security_message( port: 0 );
}

