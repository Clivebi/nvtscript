require("docker_policy_tests.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140121" );
	script_version( "2021-04-21T07:59:45+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-21 07:59:45 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-01-19 10:34:29 +0100 (Thu, 19 Jan 2017)" );
	script_name( "Docker Compliance Check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_gather_linux_host_infos.sc", "gb_docker_ssh_login_detect.sc" );
	script_mandatory_keys( "docker/info" );
	script_tag( name: "summary", value: "Runs the Docker Compliance Check.

  These tests are inspired by the CIS Docker Benchmark." );
	script_xref( name: "URL", value: "https://www.cisecurity.org/benchmark/docker/" );
	script_add_preference( name: "Perform check:", type: "checkbox", value: "no" );
	script_add_preference( name: "Report passed tests:", type: "checkbox", value: "no" );
	script_add_preference( name: "Report failed tests:", type: "checkbox", value: "yes" );
	script_add_preference( name: "Report errors:", type: "checkbox", value: "no" );
	script_add_preference( name: "Minimum docker version for test 1.1:", type: "entry", value: "1.12" );
	script_add_preference( name: "Report skipped tests:", type: "checkbox", value: "no" );
	for dt in docker_test {
		if(dt["title"]){
			script_add_preference( name: dt["title"], type: "checkbox", value: "yes" );
		}
	}
	script_tag( name: "qod", value: "98" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("docker.inc.sc");
require("docker_policy.inc.sc");
require("list_array_func.inc.sc");
docker_test_init();
if(docker_test_is_enabled( "1.0" )){
	docker_test_1_0();
}
if(docker_test_is_enabled( "1.1" )){
	docker_test_1_1();
}
if(docker_test_is_enabled( "1.2" )){
	docker_test_1_2();
}
if(docker_test_is_enabled( "1.3" )){
	docker_test_1_3();
}
if(docker_test_is_enabled( "1.4" )){
	docker_test_1_4();
}
if(docker_test_is_enabled( "1.5" )){
	docker_test_1_5();
}
if(docker_test_is_enabled( "1.6" )){
	docker_test_1_6();
}
if(docker_test_is_enabled( "1.7" )){
	docker_test_1_7();
}
if(docker_test_is_enabled( "1.8" )){
	docker_test_1_8();
}
if(docker_test_is_enabled( "1.9" )){
	docker_test_1_9();
}
if(docker_test_is_enabled( "2.0" )){
	docker_test_2_0();
}
if(docker_test_is_enabled( "2.1" )){
	docker_test_2_1();
}
if(docker_test_is_enabled( "2.2" )){
	docker_test_2_2();
}
if(docker_test_is_enabled( "2.3" )){
	docker_test_2_3();
}
if(docker_test_is_enabled( "2.4" )){
	docker_test_2_4();
}
if(docker_test_is_enabled( "2.5" )){
	docker_test_2_5();
}
if(docker_test_is_enabled( "2.6" )){
	docker_test_2_6();
}
if(docker_test_is_enabled( "2.7" )){
	docker_test_2_7();
}
if(docker_test_is_enabled( "2.8" )){
	docker_test_2_8();
}
if(docker_test_is_enabled( "2.9" )){
	docker_test_2_9();
}
if(docker_test_is_enabled( "3.0" )){
	docker_test_3_0();
}
if(docker_test_is_enabled( "3.1" )){
	docker_test_3_1();
}
if(docker_test_is_enabled( "3.2" )){
	docker_test_3_2();
}
if(docker_test_is_enabled( "3.3" )){
	docker_test_3_3();
}
if(docker_test_is_enabled( "3.4" )){
	docker_test_3_4();
}
if(docker_test_is_enabled( "3.5" )){
	docker_test_3_5();
}
if(docker_test_is_enabled( "3.6" )){
	docker_test_3_6();
}
if(docker_test_is_enabled( "3.7" )){
	docker_test_3_7();
}
if(docker_test_is_enabled( "3.8" )){
	docker_test_3_8();
}
if(docker_test_is_enabled( "3.9" )){
	docker_test_3_9();
}
if(docker_test_is_enabled( "4.0" )){
	docker_test_4_0();
}
if(docker_test_is_enabled( "4.1" )){
	docker_test_4_1();
}
if(docker_test_is_enabled( "4.2" )){
	docker_test_4_2();
}
if(docker_test_is_enabled( "4.3" )){
	docker_test_4_3();
}
if(docker_test_is_enabled( "4.4" )){
	docker_test_4_4();
}
if(docker_test_is_enabled( "4.5" )){
	docker_test_4_5();
}
if(docker_test_is_enabled( "4.6" )){
	docker_test_4_6();
}
if(docker_test_is_enabled( "4.7" )){
	docker_test_4_7();
}
if(docker_test_is_enabled( "4.8" )){
	docker_test_4_8();
}
if(docker_test_is_enabled( "4.9" )){
	docker_test_4_9();
}
if(docker_test_is_enabled( "5.0" )){
	docker_test_5_0();
}
if(docker_test_is_enabled( "5.1" )){
	docker_test_5_1();
}
if(docker_test_is_enabled( "5.2" )){
	docker_test_5_2();
}
if(docker_test_is_enabled( "5.3" )){
	docker_test_5_3();
}
if(docker_test_is_enabled( "5.4" )){
	docker_test_5_4();
}
if(docker_test_is_enabled( "5.5" )){
	docker_test_5_5();
}
if(docker_test_is_enabled( "5.6" )){
	docker_test_5_6();
}
if(docker_test_is_enabled( "5.7" )){
	docker_test_5_7();
}
if(docker_test_is_enabled( "5.8" )){
	docker_test_5_8();
}
docker_test_end();
exit( 0 );

