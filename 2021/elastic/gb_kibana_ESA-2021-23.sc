CPE = "cpe:/a:elastic:kibana";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117700" );
	script_version( "2021-09-27T11:52:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-27 11:52:39 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-27 11:31:59 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2021-37936" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Elastic Kibana HTML Injection Vulnerability (ESA-2021-23)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elastic_kibana_detect_http.sc" );
	script_mandatory_keys( "elastic/kibana/detected" );
	script_tag( name: "summary", value: "Elastic Kibana is prone to an HTML injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that kibana was not sanitizing document fields
  containing html snippets. Using this vulnerability, an attacker with the ability to write
  documents to an elasticsearch index could inject HTML. When the Discover app highlighted a search
  term containing the HTML, it would be rendered for the user." );
	script_tag( name: "affected", value: "Elastic Kibana version 7.14.0 only." );
	script_tag( name: "solution", value: "Update to version 7.14.1 or later.

  Mitigation: Users can set 'doc_table:highlight' to 'false' in the Kibana Advanced Settings." );
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
if(version_is_equal( version: version, test_version: "7.14.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.14.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

