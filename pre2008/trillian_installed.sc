if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11428" );
	script_version( "$Revision: 10200 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-06-14 16:39:20 +0200 (Thu, 14 Jun 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2002-2162" );
	script_bugtraq_id( 5677, 5733, 5755, 5765, 5769, 5775, 5776, 5777, 5783 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Trillian is installed" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 Xue Yong Zhi" );
	script_family( "Peer-To-Peer File Sharing" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "The remote host is using Trillian - a p2p software,
  which may not be suitable for a business environment." );
	script_tag( name: "solution", value: "Uninstall this software" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	name = registry_get_sz( key: key + item, item: "DisplayName" );
	if(name == "Trillian"){
		security_message( port: 0 );
		exit( 0 );
	}
}
exit( 99 );

