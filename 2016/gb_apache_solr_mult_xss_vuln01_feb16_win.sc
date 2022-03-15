CPE = "cpe:/a:apache:solr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108883" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2015-8795" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-01 14:45:30 +0530 (Tue, 01 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Solr Multiple Cross-Site Scripting Vulnerabilities (SOLR-7346) (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apache Solr and
  is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to an improper sanitization of user
  supplied input in 'webapp/web/js/scripts/analysis.js' and 'webapp/web/js/scripts/schema-browser.js.'
  files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via crafted fields." );
	script_tag( name: "affected", value: "Apache Solr versions 4.10.2, 5.0." );
	script_tag( name: "solution", value: "Update to version 5.1.0, 6.0.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/SOLR-7346" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_apache_solr_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/solr/detected", "Host/runs_windows" );
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
if(version_is_equal( version: version, test_version: "5.0" ) || version_is_equal( version: version, test_version: "5.0.0" ) || version_is_equal( version: version, test_version: "4.10.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.1.0, 6.0.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

