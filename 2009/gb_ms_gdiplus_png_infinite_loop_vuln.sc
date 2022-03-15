if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800700" );
	script_version( "2020-06-09T10:15:40+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 10:15:40 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-1511" );
	script_bugtraq_id( 34586 );
	script_name( "Microsoft GDIPlus PNG Infinite Loop Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8466" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause denial
  of service." );
	script_tag( name: "affected", value: "Microsoft Windows XP Service Pack 3 and prior." );
	script_tag( name: "insight", value: "This flaw is caused while processing crafted PNG file
  containing a large btChunkLen value which causes the control to enter an
  infinite loop." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Windows XP Operating System with GDI
  libraries installed which is prone to Infinite Loop vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
if(hotfix_check_sp( xp: 4 ) > 0){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

