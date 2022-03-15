if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11888" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 8826 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2003-0717" );
	script_xref( name: "IAVA", value: "2003-B-0007" );
	script_name( "Buffer Overrun in Messenger Service (828035)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 Jeff Adams" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "A security vulnerability exists in the Messenger Service that could allow
  arbitrary code execution on an affected system.

  This plugin determined by reading the remote registry that the patch MS03-043 has not been applied." );
	script_tag( name: "impact", value: "An attacker who successfully
  exploited this vulnerability could be able to run code with Local System
  privileges on an affected system, or could cause the Messenger Service to fail.
  Disabling the Messenger Service will prevent the possibility of attack." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-043" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( nt: 7, win2k: 5, xp: 2, win2003: 1 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "KB828035" ) > 0){
	security_message( port: 0 );
}

