if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11425" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2006-03-26 18:10:09 +0200 (Sun, 26 Mar 2006)" );
	script_bugtraq_id( 1307, 132, 246, 2664, 3226, 3813, 929 );
	script_cve_id( "CVE-1999-1418", "CVE-1999-1440", "CVE-2000-0046", "CVE-2000-0564", "CVE-2000-0552", "CVE-2001-0367", "CVE-2002-0028", "CVE-2001-1305" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "ICQ is installed" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 Xue Yong Zhi" );
	script_family( "Peer-To-Peer File Sharing" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "solution", value: "Uninstall this software." );
	script_tag( name: "summary", value: "The remote host is using ICQ - a p2p software,
  which may not be suitable for a business environment." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("smb_nt.inc.sc");
rootfile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ICQ", item: "DisplayName" );
if(rootfile){
	security_message( get_kb_item( "SMB/transport" ) );
	exit( 0 );
}
rootfile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ICQLite", item: "DisplayName" );
if(rootfile){
	security_message( get_kb_item( "SMB/transport" ) );
	exit( 0 );
}

