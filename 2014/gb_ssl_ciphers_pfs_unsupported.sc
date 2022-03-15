if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105092" );
	script_version( "$Revision: 4736 $" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "$Date: 2016-12-10 12:17:19 +0100 (Sat, 10 Dec 2016) $" );
	script_tag( name: "creation_date", value: "2014-09-23 14:16:10 +0100 (Tue, 23 Sep 2014)" );
	script_name( "SSL/TLS: Perfect Forward Secrecy Cipher Suites Missing" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssl_ciphers_pfs_supported.sc" );
	script_mandatory_keys( "SSL/PFS/no_ciphers" );
	script_tag( name: "summary", value: "The remote service is missing support for SSL/TLS cipher suites supporting Perfect Forward Secrecy." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
port = get_kb_item( "SSL/PFS/no_ciphers/port" );
if(!port){
	exit( 0 );
}
log_message( port: port, data: "The remote service does not support perfect forward secrecy cipher suites." );
exit( 0 );

