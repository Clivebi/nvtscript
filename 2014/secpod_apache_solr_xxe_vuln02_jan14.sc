CPE = "cpe:/a:apache:solr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903509" );
	script_version( "2021-08-04T10:08:11+0000" );
	script_cve_id( "CVE-2013-6407", "CVE-2012-6612" );
	script_bugtraq_id( 64008, 64427 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-04 10:08:11 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-01-29 16:29:04 +0530 (Wed, 29 Jan 2014)" );
	script_name( "Apache Solr XML External Entity (XXE) Vulnerability (SOLR-3895, SOLR-5520) (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Apache Solr and is prone to xml external entity
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to error in 'UpdateRequestHandler' and 'XPathEntityProcessor'
  when parsing XML entities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain potentially
  sensitive information, cause denial of service and potentially perform
  other more advanced XXE attacks." );
	script_tag( name: "affected", value: "Apache Solr versions before 3.6.3 and 4.x before version 4.1.0." );
	script_tag( name: "solution", value: "Update to version 3.6.3, 4.1.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55542" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2013/11/29/2" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/SOLR-3895" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/SOLR-5520" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_apache_solr_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/solr/detected", "Host/runs_unixoide" );
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
if( version_is_less( version: version, test_version: "3.6.3" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.3, 4.1.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(IsMatchRegexp( version, "^4\\.0" ) && version_is_less( version: version, test_version: "4.1.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "4.1.0", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

