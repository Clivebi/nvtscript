CPE = "cpe:/a:splunk:splunk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106262" );
	script_version( "$Revision: 12338 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-19 11:58:34 +0700 (Mon, 19 Sep 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2176" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Splunk Enterprise Multiple OpenSSL Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_splunk_detect.sc" );
	script_mandatory_keys( "Splunk/installed" );
	script_tag( name: "summary", value: "Splunk Enterprise is prone to multiple OpenSSL vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Splunk Enterprise is affected by multiple OpenSSL vulnerabilities." );
	script_tag( name: "affected", value: "Splunk Enterprise 6.4.x, 6.3.x, 6.2.x, 6.1.x, 6.0.x and 5.0.x" );
	script_tag( name: "solution", value: "Update to version 6.4.2, 6.3.6, 6.2.10, 6.1.11, 6.0.12 or later." );
	script_xref( name: "URL", value: "https://www.splunk.com/view/SP-CAAAPQM" );
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
	if(version_is_less( version: version, test_version: "6.4.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.4.2" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.3" )){
	if(version_is_less( version: version, test_version: "6.3.6" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.3.6" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.2" )){
	if(version_is_less( version: version, test_version: "6.2.10" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.2.10" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.1" )){
	if(version_is_less( version: version, test_version: "6.1.11" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.1.11" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(version_is_less( version: version, test_version: "6.0.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.12" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

