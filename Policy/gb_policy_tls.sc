if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105778" );
	script_version( "2021-01-26T10:23:02+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-26 10:23:02 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-06-28 11:57:08 +0200 (Tue, 28 Jun 2016)" );
	script_name( "SSL/TLS: Policy Check" );
	script_category( ACT_GATHER_INFO );
	script_family( "Policy" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_tls_version_get.sc", "compliance_tests.sc" );
	script_mandatory_keys( "ssl_tls/port" );
	script_add_preference( name: "Minimum allowed TLS version:", type: "radio", value: "TLS 1.2;TLS 1.1;TLS 1.0;SSL v3", id: 1 );
	script_add_preference( name: "Perform check:", type: "checkbox", value: "no", id: 2 );
	script_add_preference( name: "Report passed tests:", type: "checkbox", value: "no", id: 3 );
	script_tag( name: "summary", value: "This VT is running SSL/TLS Policy Checks." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("ssl_funcs.inc.sc");
require("misc_func.inc.sc");
require("policy_functions.inc.sc");
title = "Minimum supported TLS version";
solution = "Disable SSL / TLS version";
test_type = "TLS / SSL Handshake";
test = "Perform handshake";
minimum_TLS = script_get_preference( name: "Minimum allowed TLS version:", id: 1 );
compliant = "yes";
pf = script_get_preference( name: "Perform check:", id: 2 );
if(tolower( pf ) != "yes"){
	exit( 0 );
}
if( !port = tls_ssl_get_port() ){
	value = "Error";
	compliant = "incomplete";
	comment = "No TLS / SSL port found.";
}
else {
	if( !supported_versions = get_kb_list( "tls_version_get/" + port + "/version" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "No TLS / SSL version detected.";
	}
	else {
		set_kb_item( name: "tls_policy/perform_test", value: TRUE );
		rpt = script_get_preference( name: "Report passed tests:", id: 3 );
		if(rpt == "yes"){
			set_kb_item( name: "tls_policy/report_passed_tests", value: TRUE );
		}
		set_kb_item( name: "tls_policy/minimum_TLS", value: minimum_TLS );
		supported_versions = sort( supported_versions );
		ssl["SSLv2"] = SSL_v2;
		ssl["SSLv3"] = SSL_v3;
		ssl["TLSv1.0"] = TLS_10;
		ssl["TLSv1.1"] = TLS_11;
		ssl["TLSv1.2"] = TLS_12;
		ssl["TLSv1.3"] = TLS_13;
		if(minimum_TLS == "SSL v3"){
			mtls = SSL_v3;
		}
		if(minimum_TLS == "TLS 1.0"){
			mtls = TLS_10;
		}
		if(minimum_TLS == "TLS 1.1"){
			mtls = TLS_11;
		}
		if(minimum_TLS == "TLS 1.2"){
			mtls = TLS_12;
		}
		if(minimum_TLS == "TLS 1.3"){
			mtls = TLS_13;
		}
		for sv in supported_versions {
			if(ssl[sv] < mtls){
				policy_violating_ssl_versions += version_string[ssl[sv]] + " ";
				compliant = "no";
			}
			value += ", " + sv;
		}
		if( value ){
			value = str_replace( string: value, find: ", ", replace: "", count: 1 );
			comment = "Port: " + port;
		}
		else {
			value = "None";
			compliant = "incomplete";
			comment = "Port: " + port + ": Can not get information about supported SSL / TLS version";
		}
		if( policy_violating_ssl_versions ) {
			set_kb_item( name: "tls_policy/policy_violating_ssl_versions/" + port, value: policy_violating_ssl_versions );
		}
		else {
			set_kb_item( name: "tls_policy/test_passed/" + port, value: TRUE );
		}
	}
}
policy_reporting( result: value, default: minimum_TLS, compliant: compliant, fixtext: solution, type: test_type, test: test, info: comment );
policy_set_kbs( type: test_type, cmd: test, default: minimum_TLS, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

