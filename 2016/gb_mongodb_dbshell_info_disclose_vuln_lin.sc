CPE = "cpe:/a:mongodb:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809350" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_cve_id( "CVE-2016-6494" );
	script_bugtraq_id( 92204 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-10-13 15:38:52 +0530 (Thu, 13 Oct 2016)" );
	script_name( "MongoDB Client 'dbshell' Information Disclosure Vulnerability (Linux)" );
	script_tag( name: "summary", value: "The host is installed with MongoDB
  and is prone to information disclousre vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw is due to mongodb-clients stores
  its history in '~/.dbshell', this file is created with permissions 0644. Home
  folders are world readable as well." );
	script_tag( name: "impact", value: "Successful exploitation will allow local users
  to obtain sensitive information by reading .dbshell history files." );
	script_tag( name: "affected", value: "MongoDB version 2.4.10 on Linux" );
	script_tag( name: "solution", value: "Upgrade to MongoDB version 3.0, or 3.2
  or 3.3.14, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://jira.mongodb.org/browse/SERVER-25335" );
	script_xref( name: "URL", value: "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832908" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "gb_mongodb_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/mongodb", 27017 );
	script_mandatory_keys( "mongodb/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!mbPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!mongodbversion = get_app_version( cpe: CPE, port: mbPort )){
	exit( 0 );
}
if(ContainsString( mongodbversion, "-rc" )){
	mongodbversion = ereg_replace( pattern: "-", replace: ".", string: mongodbversion );
}
if(version_is_equal( version: mongodbversion, test_version: "2.4.10" )){
	report = report_fixed_ver( installed_version: mongodbversion, fixed_version: "3.0 or 3.2 or 3.3.14" );
	security_message( data: report, port: mbPort );
	exit( 0 );
}

