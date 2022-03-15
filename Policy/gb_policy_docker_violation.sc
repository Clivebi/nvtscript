if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140122" );
	script_version( "2021-05-17T12:20:05+0000" );
	script_tag( name: "last_modification", value: "2021-05-17 12:20:05 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2017-01-19 10:35:52 +0100 (Thu, 19 Jan 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod", value: "98" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Docker Compliance Check: Failed" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "Policy/gb_policy_docker.sc" );
	script_mandatory_keys( "docker/docker_test/has_failed_tests", "docker/docker_test/report_failed" );
	script_tag( name: "summary", value: "Lists all the Docker Compliance Policy Checks which did NOT pass." );
	script_tag( name: "solution", value: "Update or reconfigure the affected service / system / host according to the
  policy requirement." );
	exit( 0 );
}
require("docker.inc.sc");
require("docker_policy_tests.inc.sc");
require("docker_policy.inc.sc");
if(!f = get_kb_list( "docker/docker_test/failed/*" )){
	exit( 0 );
}
failed_count = max_index( keys( f ) );
if(failed_count == 0){
	exit( 0 );
}
report = failed_count + " Checks failed:\n\n";
for failed in sort( keys( f ) ) {
	_id = eregmatch( pattern: "docker/docker_test/failed/([0-9.]+)", string: failed );
	if(isnull( _id[1] )){
		continue;
	}
	id = _id[1];
	reason = chomp( f[failed] );
	data = get_docker_test_data( id: id );
	report += " - " + data["title"] + "\n\nDescription: " + data["desc"] + "\nSolution: " + data["solution"] + "\n\nResult: " + reason + "\n\n";
}
security_message( port: 0, data: chomp( report ) );
exit( 0 );

