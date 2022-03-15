if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15467" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 11380 );
	script_cve_id( "CVE-2004-0569" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Vulnerability in RPC Runtime Library Could Allow Information Disclosure and Denial of Service (873350)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 Noam Rathaus" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "An information disclosure and denial of service vulnerability exists when
  the RPC Runtime Library processes specially crafted messages." );
	script_tag( name: "impact", value: "An attacker who successfully exploited this vulnerability could potentially
  read portions of active memory or cause the affected system to stop responding." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-029" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( nt: 7 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "873350" ) > 0){
	security_message( port: 0 );
}

