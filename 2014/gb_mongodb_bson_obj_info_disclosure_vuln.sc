CPE = "cpe:/a:mongodb:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804246" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_cve_id( "CVE-2012-6619" );
	script_bugtraq_id( 64687 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2014-03-14 18:12:20 +0530 (Fri, 14 Mar 2014)" );
	script_name( "MongoDB BSON Object Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is running MongoDB and
  is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in the application
  which fails to properly validate incorrect length of an BSON object" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote authenticated users to access sensitive information stored in the
  server process memory." );
	script_tag( name: "affected", value: "MongoDB version prior to 2.3.2 on Windows" );
	script_tag( name: "solution", value: "Upgrade to MongoDB version 2.3.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://jira.mongodb.org/browse/SERVER-7769" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_mongodb_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/mongodb", 27017 );
	script_mandatory_keys( "mongodb/installed", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!mbPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: mbPort )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "2.3.2" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.3.2" );
	security_message( data: report, port: mbPort );
	exit( 0 );
}

