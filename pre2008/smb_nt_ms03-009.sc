if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11433" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 7145 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2003-0011" );
	script_name( "Microsoft ISA Server DNS - Denial Of Service (MS03-009)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 A.D.Consulting" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "solution", value: "The vendor has releases updates, please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-009" );
	script_tag( name: "summary", value: "A flaw exists in the ISA Server DNS intrusion detection application filter.
  An attacker could exploit the vulnerability by sending a specially formed
  request to an ISA Server computer that is publishing a DNS server, which
  could then result in a denial of service to the published DNS server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
fpc = get_kb_item( "SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc" );
if(!fpc){
	exit( 0 );
}
fix = get_kb_item( "SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/256" );
if(!fix){
	security_message( port: 0 );
}

