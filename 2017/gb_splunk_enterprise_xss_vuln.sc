CPE = "cpe:/a:splunk:splunk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106713" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-04-03 09:45:47 +0700 (Mon, 03 Apr 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Splunk Enterprise XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_splunk_detect.sc" );
	script_mandatory_keys( "Splunk/installed" );
	script_tag( name: "summary", value: "Splunk Enterprise is prone to a persistent cross-site scripting
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Splunk Enterprise is affected by a vulnerability that allows an attacker to
inject and store arbitrary script. However, the attacker has to be authenticated in Splunk web before exploiting
this vulnerability." );
	script_tag( name: "affected", value: "Splunk Enterprise 6.2.x, 6.3.x, 6.4.x and 6.5.x." );
	script_tag( name: "solution", value: "Update to version 6.2.14, 6.3.10, 6.4.6, 6.5.3 or
later." );
	script_xref( name: "URL", value: "https://www.splunk.com/view/SP-CAAAPZ3" );
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
if(IsMatchRegexp( version, "^6\\.2" )){
	if(version_is_less( version: version, test_version: "6.2.14" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.2.14" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.3" )){
	if(version_is_less( version: version, test_version: "6.3.10" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.3.10" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.4" )){
	if(version_is_less( version: version, test_version: "6.4.6" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.4.6" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^6\\.5" )){
	if(version_is_less( version: version, test_version: "6.5.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.5.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

