CPE = "cpe:/a:splunk:splunk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106399" );
	script_version( "$Revision: 12363 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-18 13:29:17 +0700 (Fri, 18 Nov 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-5636", "CVE-2016-5699", "CVE-2016-0772" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Splunk Enterprise Multiple Vulnerabilities (Nov 2016)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_splunk_detect.sc" );
	script_mandatory_keys( "Splunk/installed" );
	script_tag( name: "summary", value: "Splunk Enterprise is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Splunk Enterprise is affected by multiple vulnerabilities:

  - Multiple Vulnerabilities in Python (CVE-2016-5636, CVE-2016-5699, CVE-2016-0772)

  - HTTP Request Injection in Splunk Web: Splunk Enterprise versions is affected by an HTTP request injection
vulnerability that permits leakage of authentication tokens. The authorization tokens permit an attacker to use
the Splunk REST API with the same rights as the user." );
	script_tag( name: "impact", value: "An attacker may obtain an authentication token which might give complete
access depending on the attacked user." );
	script_tag( name: "affected", value: "Splunk Enterprise 6.4.x, 6.3.x, 6.2.x, 6.1.x, 6.0.x and 5.0.x" );
	script_tag( name: "solution", value: "Update to version 6.4.4, 6.3.8, 6.2.12, 6.1.12, 6.0.13, 5.0.17 or later." );
	script_xref( name: "URL", value: "http://www.splunk.com/view/SP-CAAAPSR" );
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
	if(version_is_less( version: version, test_version: "6.4.4" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.4.4" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.3" )){
	if(version_is_less( version: version, test_version: "6.3.8" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.3.8" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.2" )){
	if(version_is_less( version: version, test_version: "6.2.12" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.2.12" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.1" )){
	if(version_is_less( version: version, test_version: "6.1.12" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.1.12" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.0" )){
	if(version_is_less( version: version, test_version: "6.0.13" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.0.13" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(version_is_less( version: version, test_version: "5.0.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.17" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

