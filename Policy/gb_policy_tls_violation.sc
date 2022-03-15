if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105780" );
	script_version( "2020-03-31T06:57:15+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-03-31 06:57:15 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-06-28 14:30:12 +0200 (Tue, 28 Jun 2016)" );
	script_name( "SSL/TLS: Policy Check Violations" );
	script_category( ACT_END );
	script_family( "Policy" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "Policy/gb_policy_tls.sc" );
	script_mandatory_keys( "tls_policy/perform_test", "ssl_tls/port" );
	script_tag( name: "summary", value: "SSL/TLS Policy Check Violations." );
	script_tag( name: "solution", value: "Update or reconfigure the affected service / system / host according to the
  policy requirement." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
policy_violating_ssl_versions = get_kb_item( "tls_policy/policy_violating_ssl_versions/" + port );
if(!policy_violating_ssl_versions){
	exit( 0 );
}
minimum_TLS = get_kb_item( "tls_policy/minimum_TLS" );
report = "Minimum allowed SSL/TLS version: " + minimum_TLS + "\n\n";
report += "The following SSL/TLS versions are supported by the remote service and violating the SSL/TLS policy:\n\n";
report += str_replace( string: policy_violating_ssl_versions, find: " ", replace: "\n" );
security_message( port: port, data: report );
exit( 0 );

