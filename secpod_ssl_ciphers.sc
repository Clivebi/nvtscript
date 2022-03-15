if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900234" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-13 17:43:57 +0200 (Tue, 13 Apr 2010)" );
	script_name( "SSL/TLS: Check Supported Cipher Suites" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_ssl_ciphers_setting.sc", "gb_ssl_sni_supported.sc", "gb_tls_version_get.sc" );
	script_family( "SSL and TLS" );
	script_mandatory_keys( "ssl_tls/port" );
	script_tag( name: "summary", value: "This routine connects to a SSL/TLS service and checks the quality of
  the accepted cipher suites.

  Note: Depending on the amount of services offered by this host, the routine might take good amount of time to complete,
  it is advised to increase the timeout." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_timeout( 3600 );
	exit( 0 );
}
require("mysql.inc.sc");
require("misc_func.inc.sc");
require("ssl_funcs.inc.sc");
require("secpod_ssl_ciphers.inc.sc");
require("byte_func.inc.sc");
require("list_array_func.inc.sc");
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!tls_versions = get_kb_list( "tls_version_get/" + port + "/version" )){
	exit( 0 );
}
tls_type = get_kb_item( "starttls_typ/" + port );
set_kb_item( name: "secpod_ssl_ciphers/started", value: TRUE );
if( tls_type && tls_type == "mysql" ) {
	check_single_cipher( tls_versions: tls_versions, port: port );
}
else {
	check_all_cipher( tls_versions: tls_versions, port: port );
}
exit( 0 );

