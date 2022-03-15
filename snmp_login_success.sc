if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108542" );
	script_version( "$Revision: 13257 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-24 09:14:40 +0100 (Thu, 24 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2019-01-24 09:05:25 +0100 (Thu, 24 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SNMP Login Successful For Authenticated Checks" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SNMP" );
	script_dependencies( "snmp_detect.sc" );
	script_mandatory_keys( "login/SNMP/success" );
	script_tag( name: "summary", value: "It was possible to login using the provided SNMPv1 /
  SNMPv2 community string / SNMPv3 credentials. Hence version checks based on SNMP are working." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
port = get_kb_item( "login/SNMP/success/port" );
if(!port){
	port = 0;
}
log_message( port: port, proto: "udp" );
exit( 0 );

