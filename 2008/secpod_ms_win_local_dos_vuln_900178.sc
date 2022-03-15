if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900178" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)" );
	script_cve_id( "CVE-2008-5044" );
	script_bugtraq_id( 32206 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:N/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_name( "Microsoft Windows 'UnhookWindowsHookEx' Local DoS Vulnerability" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "http://killprog.com/whk.zip" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/498165" );
	script_tag( name: "impact", value: "Attackers may exploit this issue to deny service to legitimate users." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2003 Service Pack 2 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This Microsoft Windows host is prone to denial of service
  vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to error in 'UnhookWindowsHookEx' function. This can
  be exploited to cause system hang." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
if(hotfix_check_sp( win2003: 3 ) <= 0){
	exit( 0 );
}
security_message( port: 0, data: "The target host was found to be vulnerable" );

