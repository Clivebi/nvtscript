if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105091" );
	script_version( "2021-03-19T08:13:38+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 08:13:38 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-09-23 14:29:22 +0100 (Tue, 23 Sep 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: SMTP Missing Support For STARTTLS" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_starttls_smtp.sc" );
	script_mandatory_keys( "smtp/starttls/not_supported" );
	script_tag( name: "summary", value: "The remote SMTP server does not support the 'STARTTLS' command." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
port = get_kb_item( "smtp/starttls/not_supported/port" );
if(!port){
	exit( 0 );
}
log_message( port: port, data: "The remote SMTP server does not support the 'STARTTLS' command." );
exit( 0 );

