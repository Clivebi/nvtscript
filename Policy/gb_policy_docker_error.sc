if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140124" );
	script_version( "2021-05-17T12:20:05+0000" );
	script_tag( name: "last_modification", value: "2021-05-17 12:20:05 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2017-01-19 11:24:37 +0100 (Thu, 19 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "98" );
	script_name( "Docker Compliance Check: Error" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "Policy/gb_policy_docker.sc" );
	script_mandatory_keys( "docker/docker_test/has_error_tests", "docker/docker_test/report_errors" );
	script_tag( name: "summary", value: "Lists all the Docker Compliance Policy Checks errors." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("docker.inc.sc");
require("docker_policy_tests.inc.sc");
require("docker_policy.inc.sc");
if(!f = get_kb_list( "docker/docker_test/error/*" )){
	exit( 0 );
}
error_count = max_index( keys( f ) );
if(error_count == 0){
	exit( 0 );
}
report = error_count + " errors occurred during the test:\n\n";
for error in sort( keys( f ) ) {
	_id = eregmatch( pattern: "docker/docker_test/error/([0-9.]+)", string: error );
	if(isnull( _id[1] )){
		continue;
	}
	id = _id[1];
	reason = chomp( f[error] );
	data = get_docker_test_data( id: id );
	report += " - " + data["title"] + "\n\nError: " + reason + "\n\n";
}
log_message( port: 0, data: chomp( report ) );
exit( 0 );

