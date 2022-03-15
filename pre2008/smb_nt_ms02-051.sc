if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11146" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5410, 5711, 5712 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-0863", "CVE-2002-0864" );
	script_name( "Microsoft RDP flaws could allow sniffing and DOS(Q324380)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2002 SECNAP Network Security, LLC" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "Remote Data Protocol (RDP) version 5.0 in Microsoft
  Windows 2000 and RDP 5.1 in Windows XP does not encrypt the checksums of plaintext session
  data, which could allow a remote attacker to determine the contents of encrypted sessions
  via sniffing, and Remote Data Protocol (RDP) version 5.1 in Windows XP allows remote
  attackers to cause a denial of service (crash) when Remote Desktop is enabled via a PDU
  Confirm Active data packet that does not set the Pattern BLT command." );
	script_tag( name: "impact", value: "Two vulnerabilities: information disclosure, denial of service." );
	script_tag( name: "affected", value: "- Microsoft Windows 2000

  - Microsoft Windows XP" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-051" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( xp: 1, win2k: 4 ) <= 0){
	exit( 0 );
}
if(hotfix_check_nt_server() <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "Q324380" ) > 0){
	security_message( port: 0 );
}

