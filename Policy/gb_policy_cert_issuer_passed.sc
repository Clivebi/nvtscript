if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140039" );
	script_version( "2020-03-31T06:57:15+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-31 06:57:15 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-11-01 10:14:30 +0100 (Tue, 01 Nov 2016)" );
	script_name( "SSL/TLS: Cert Issuer Policy Check Passed" );
	script_category( ACT_GATHER_INFO );
	script_family( "Policy" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "Policy/gb_policy_cert_issuer.sc" );
	script_mandatory_keys( "ssl_tls/port", "policy_cert_issuer/check_issuer", "policy_cert_issuer/report_passed_tests", "policy_cert_issuer/run_test" );
	script_tag( name: "summary", value: "This script reports if the SSL/TLS certificate is signed by the given issuer." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!passed = get_kb_item( "policy_cert_issuer/" + port + "/passed" )){
	exit( 0 );
}
issuer = get_kb_item( "policy_cert_issuer/" + port + "/issuer" );
check_issuer = get_kb_item( "policy_cert_issuer/check_issuer" );
report = "The issuer `" + issuer + "` of the certificate is matching the given issuer `" + check_issuer + "`.";
log_message( port: port, data: report );
exit( 0 );

