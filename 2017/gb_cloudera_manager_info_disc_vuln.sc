CPE = "cpe:/a:cloudera:cloudera_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106786" );
	script_version( "2020-11-12T09:36:23+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-04-25 08:10:42 +0200 (Tue, 25 Apr 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Cloudera Manager Configuration Download Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_cloudera_manager_detect.sc" );
	script_mandatory_keys( "cloudera_manager/installed" );
	script_tag( name: "summary", value: "Cloudera Manager is prone to an information disclosure vulnerability where
a unauthenticated attacker may download module configurations." );
	script_tag( name: "vuldetect", value: "Tries to download a module configuration." );
	script_tag( name: "insight", value: "Cloudera Manager allows to download module configurations without
authentication by iterating on the module index." );
	script_tag( name: "solution", value: "The vulnerability can be mitigated by requiring authentication by
setting 'client_config_auth'." );
	script_xref( name: "URL", value: "https://github.com/wavestone-cdt/hadoop-attack-library/tree/master/Third-party%20modules%20vulnerabilities/Cloudera%20Manager/Unauthenticated%20configuration%20download" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
for(i = 1;i <= 20;i++){
	url = "/cmf/services/" + i + "/client-config";
	if(http_vuln_check( port: port, url: url, pattern: "Content-Type: application/zip", check_header: TRUE, extra_check: "Content-disposition: attachment" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

