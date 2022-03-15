CPE = "cpe:/a:mongodb:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808149" );
	script_version( "$Revision: 11922 $" );
	script_cve_id( "CVE-2013-3969" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-06-07 10:55:52 +0530 (Tue, 07 Jun 2016)" );
	script_name( "MongoDB engine_v8 Denial of Service Vulnerability (Linux)" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote authenticated users to cause a denial of service condition by
  dereferencing an uninitialized pointer." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in engine_v8 which fails
  to parse certain regular expressions." );
	script_tag( name: "solution", value: "Upgrade to MongoDB version 2.4.5 or 2.5.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running MongoDB and is prone
  to a denial of service vulnerability." );
	script_tag( name: "affected", value: "MongoDB version 2.4.0 through 2.4.4 on Linux" );
	script_xref( name: "URL", value: "http://www.mongodb.org/about/alerts" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54170" );
	script_xref( name: "URL", value: "https://jira.mongodb.org/browse/SERVER-9878" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_family( "Databases" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_mongodb_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/mongodb", 27017 );
	script_mandatory_keys( "mongodb/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( ver, "^2\\.4" )){
	if(version_in_range( version: ver, test_version: "2.4.0", test_version2: "2.4.4" )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "2.4.5" );
		security_message( data: report, port: port );
		exit( 0 );
	}
}

