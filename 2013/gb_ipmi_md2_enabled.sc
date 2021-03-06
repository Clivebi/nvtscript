if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103839" );
	script_version( "$Revision: 11865 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-11-26 12:33:03 +0100 (Tue, 26 Nov 2013)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "IPMI MD2 Auth Type Support Enabled" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_ipmi_detect.sc" );
	script_require_udp_ports( "Services/udp/ipmi", 623 );
	script_mandatory_keys( "ipmi/md2_supported" );
	script_tag( name: "solution", value: "Disable MD2 auth type support." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "summary", value: "IPMI MD2 auth type support is enabled on the remote host." );
	exit( 0 );
}
port = get_kb_item( "Services/udp/ipmi" );
if(!port){
	exit( 0 );
}
if(!get_udp_port_state( port )){
	exit( 0 );
}
if(get_kb_item( "ipmi/md2_supported" )){
	security_message( port: port, proto: "udp" );
	exit( 0 );
}
exit( 99 );

