if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15822" );
	script_version( "$Revision: 10200 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-06-14 16:39:20 +0200 (Thu, 14 Jun 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2002-1059" );
	script_bugtraq_id( 5287 );
	script_xref( name: "OSVDB", value: "4991" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "SecureCRT SSH1 protocol version string overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "The remote host is using a vulnerable version of SecureCRT, a
  SSH/Telnet client built for Microsoft Windows operation systems." );
	script_tag( name: "impact", value: "It has been reported that SecureCRT contain a remote buffer overflow
  allowing an SSH server to execute arbitrary command via a specially
  long SSH1 protocol version string." );
	script_tag( name: "solution", value: "Upgrade to SecureCRT 3.2.2, 3.3.4, 3.4.6, 4.1 or newer" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
key_list = make_list( "SOFTWARE\\VanDyke\\SecureCRT\\License\\",
	 "SOFTWARE\\VanDyke\\SecureCRT\\Evaluation License\\" );
for key in key_list {
	if(!registry_key_exists( key: key )){
		continue;
	}
	version = registry_get_sz( key: key, item: "Version" );
	if(version && egrep( pattern: "^(2\\.|3\\.([01]|2[^.]|2\\.1[^0-9]|3[^.]|3\\.[1-3][^0-9]|4[^.]|4\\.[1-5][^0-9])|4\\.0 beta [12])", string: version )){
		security_message( port: 0 );
		exit( 0 );
	}
}
exit( 99 );

