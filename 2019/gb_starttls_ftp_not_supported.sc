if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108553" );
	script_version( "2021-03-19T08:13:38+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 08:13:38 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2019-02-26 08:10:03 +0100 (Tue, 26 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: FTP Missing Support For AUTH TLS" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "gb_starttls_ftp.sc" );
	script_mandatory_keys( "ftp/starttls/not_supported" );
	script_tag( name: "summary", value: "The remote FTP server does not support the 'AUTH TLS' command." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
port = get_kb_item( "ftp/starttls/not_supported/port" );
if(!port){
	exit( 99 );
}
log_message( port: port, data: "The remote FTP server does not support the 'AUTH TLS' command." );
exit( 0 );

