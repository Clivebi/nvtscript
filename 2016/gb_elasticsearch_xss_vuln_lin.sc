CPE = "cpe:/a:elastic:elasticsearch";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808506" );
	script_version( "2021-01-18T10:09:47+0000" );
	script_cve_id( "CVE-2014-6439" );
	script_bugtraq_id( 70233 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-01-18 10:09:47 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-06-28 18:37:05 +0530 (Tue, 28 Jun 2016)" );
	script_name( "Elasticsearch Cross-site Scripting (XSS) Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is running Elasticsearch
  and is prone to Cross-site Scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw is due to an error in the
  CORS functionality." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "affected", value: "Elasticsearch version 1.3.x and prior
  on Linux." );
	script_tag( name: "solution", value: "Update to Elasticsearch version 1.4.0.Beta1,
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.elastic.co/community/security/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/533602/100/0/threaded" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elastic_elasticsearch_detect_http.sc", "os_detection.sc" );
	script_mandatory_keys( "elastic/elasticsearch/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!esPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!esVer = get_app_version( cpe: CPE, port: esPort )){
	exit( 0 );
}
esVer1 = eregmatch( pattern: "([0-9.]+)", string: esVer );
esVer = esVer1[1];
if(version_is_less( version: esVer, test_version: "1.4.0" )){
	report = report_fixed_ver( installed_version: esVer, fixed_version: "1.4.0.Beta1" );
	security_message( data: report, port: esPort );
	exit( 0 );
}

