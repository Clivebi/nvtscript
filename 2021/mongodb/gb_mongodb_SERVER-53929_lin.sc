CPE = "cpe:/a:mongodb:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145880" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-04 02:47:18 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-03 18:10:00 +0000 (Mon, 03 May 2021)" );
	script_cve_id( "CVE-2021-20326" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MongoDB DoS Vulnerability (SERVER-53929) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_mongodb_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mongodb/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MongoDB is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A user authorized to performing a specific type of find query may
  trigger a DoS." );
	script_tag( name: "affected", value: "MongoDB versions 4.4.0 through 4.4.3." );
	script_tag( name: "solution", value: "Update to version 4.4.4 or later." );
	script_xref( name: "URL", value: "https://jira.mongodb.org/browse/SERVER-53929" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.4.0", test_version2: "4.4.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.4.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

