if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14388" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2553" );
	script_bugtraq_id( 9783 );
	script_xref( name: "OSVDB", value: "4121" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_name( "IgnitionServer Irc operator privilege escalation vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "General" );
	script_dependencies( "ircd.sc" );
	script_require_ports( "Services/irc", 6667 );
	script_mandatory_keys( "ircd/banner" );
	script_tag( name: "solution", value: "Upgrade to IgnitionServer 0.2.1-BRC1 or newer." );
	script_tag( name: "summary", value: "The remote host is running a version of the IgnitionServer IRC
  service which may be vulnerable to a flaw that let remote attacker
  to gain elevated privileges on the system." );
	script_tag( name: "impact", value: "A remote attacker, who is an operator, can supply an unofficial command
  to the server to obtain elevated privileges and become a global IRC operator." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 6667, proto: "irc" );
banner = get_kb_item( "irc/banner/" + port );
if(!banner || !ContainsString( banner, "ignitionServer" )){
	exit( 0 );
}
if(egrep( pattern: ".*ignitionServer 0\\.([01]\\.|2\\.0).*", string: banner )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

