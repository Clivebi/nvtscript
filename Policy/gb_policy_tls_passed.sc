if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105781" );
	script_version( "2020-03-31T06:57:15+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-31 06:57:15 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-06-28 15:37:57 +0200 (Tue, 28 Jun 2016)" );
	script_name( "SSL/TLS: Policy Check OK" );
	script_category( ACT_END );
	script_family( "Policy" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "Policy/gb_policy_tls.sc" );
	script_mandatory_keys( "tls_policy/perform_test", "tls_policy/report_passed_tests", "ssl_tls/port" );
	script_tag( name: "summary", value: "Shows all supported SSL/TLS versions" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!passed = get_kb_item( "tls_policy/test_passed/" + port )){
	exit( 0 );
}
minimum_TLS = get_kb_item( "tls_policy/minimum_TLS" );
supported_versions = get_kb_list( "tls_version_get/" + port + "/version" );
report = "Minimum allowed TLS version: " + minimum_TLS + "\n\n";
report += "The following SSL/TLS versions are supported by the remote service:\n\n";
for sv in sort( supported_versions ) {
	report += sv + "\n";
}
report += "\nSSL/TLS policy test passed.";
log_message( port: port, data: report );
exit( 0 );

