CPE = "cpe:/a:elastic:elasticsearch";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117697" );
	script_version( "2021-09-27T11:52:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-27 11:52:39 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-27 11:31:59 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:M/C:C/I:C/A:N" );
	script_cve_id( "CVE-2021-37937" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Elastic Elasticsearch Privilege Escalation Vulnerability (ESA-2021-25)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_elastic_elasticsearch_detect_http.sc" );
	script_mandatory_keys( "elastic/elasticsearch/detected" );
	script_tag( name: "summary", value: "Elastic Elasticsearch is prone to a privilege escalation
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An issue was found with how API keys are created with the
  fleet-server service account. When an API key is created with a service account, it is possible
  that the API key could be created with higher privileges than intended. Using this vulnerability,
  a compromised fleet-server service account could escalate themselves to a super-user." );
	script_tag( name: "affected", value: "Elastic Elasticsearch version 7.13.0 through 7.14.0." );
	script_tag( name: "solution", value: "Update to version 7.14.1 or later." );
	script_xref( name: "URL", value: "https://discuss.elastic.co/t/elastic-stack-7-14-1-security-update/283077" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "7.13.0", test_version2: "7.14.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.14.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

