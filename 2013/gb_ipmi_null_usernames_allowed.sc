if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103838" );
	script_version( "$Revision: 11865 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-11-26 12:23:03 +0100 (Tue, 26 Nov 2013)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:P/A:N" );
	script_name( "IPMI Null Usernames Allowed" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_ipmi_detect.sc" );
	script_require_udp_ports( "Services/udp/ipmi", 623 );
	script_mandatory_keys( "ipmi/null_username" );
	script_tag( name: "solution", value: "Don't allow accounts with a null username or password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "summary", value: "The remote IPMI service allows 'null usernames'." );
	exit( 0 );
}
port = get_kb_item( "Services/udp/ipmi" );
if(!port){
	exit( 0 );
}
if(!get_udp_port_state( port )){
	exit( 0 );
}
if(get_kb_item( "ipmi/null_username" )){
	security_message( port: port, proto: "udp" );
	exit( 0 );
}
exit( 99 );

