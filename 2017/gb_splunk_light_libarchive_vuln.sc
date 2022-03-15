CPE = "cpe:/a:splunk:light";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106568" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-02-06 11:21:45 +0700 (Mon, 06 Feb 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Splunk Light libarchive Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_splunk_light_detect.sc" );
	script_mandatory_keys( "SplunkLight/installed" );
	script_tag( name: "summary", value: "Splunk Light is prone to multiple vulnerabilities in libarchive." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple Vulnerabilities in libarchive addressed by version upgrade to
v3.2.2." );
	script_tag( name: "affected", value: "Splunk Light prior to version 6.5.1" );
	script_tag( name: "solution", value: "Update to version 6.5.1 or later." );
	script_xref( name: "URL", value: "http://www.splunk.com/view/SP-CAAAPW8" );
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
if(version_is_less( version: version, test_version: "6.5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.5.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

