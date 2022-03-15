CPE = "cpe:/a:apache:solr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108886" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-31 15:14:14 +0700 (Thu, 31 Aug 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-17 01:29:00 +0000 (Thu, 17 May 2018)" );
	script_cve_id( "CVE-2017-3163" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Solr Inter-Node Communication Vulnerability (SOLR-10031) (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_apache_solr_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/solr/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "When using the Index Replication feature, Apache Solr nodes can pull index
  files from a master/leader node using an HTTP API which accepts a file name. However, Solr did not validate the
  file name, hence it was possible to craft a special request involving path traversal, leaving any file readable
  to the Solr server process exposed. Solr servers protected and restricted by firewall rules and/or authentication
  would not be at risk since only trusted clients and users would gain direct HTTP access." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Solr versions before 5.5.4 and 6.x before 6.4.1." );
	script_tag( name: "solution", value: "Update to version 5.5.4, 6.4.1, 7.0.0 or later." );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/SOLR-10031" );
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
if( version_is_less( version: version, test_version: "5.5.4" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.4, 6.4.1, 7.0.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(IsMatchRegexp( version, "^6\\." ) && version_is_less( version: version, test_version: "6.4.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.4.1, 7.0.0", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

