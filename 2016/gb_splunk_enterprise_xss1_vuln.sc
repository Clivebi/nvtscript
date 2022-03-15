CPE = "cpe:/a:splunk:splunk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106265" );
	script_version( "$Revision: 12149 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-19 11:58:34 +0700 (Mon, 19 Sep 2016)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Splunk Enterprise XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_splunk_detect.sc" );
	script_mandatory_keys( "Splunk/installed" );
	script_tag( name: "summary", value: "Splunk Enterprise is prone a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Splunk Enterprise is affected by a cross-site scripting vulnerability
in the Splunk Web." );
	script_tag( name: "impact", value: "An arbitrary script may be executed on the user's web browser." );
	script_tag( name: "affected", value: "Splunk Enterprise 6.4.x and 6.3.x" );
	script_tag( name: "solution", value: "Update to version 6.4.1, 6.3.5 or later." );
	script_xref( name: "URL", value: "https://www.splunk.com/view/SP-CAAAPN9" );
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
if(IsMatchRegexp( version, "^6\\.4" )){
	if(version_is_less( version: version, test_version: "6.4.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.4.1" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.3" )){
	if(version_is_less( version: version, test_version: "6.3.5" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.3.5" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

