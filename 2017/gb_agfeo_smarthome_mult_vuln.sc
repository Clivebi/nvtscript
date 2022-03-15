CPE = "cpe:/a:agfeo:smarthome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106965" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-07-18 15:36:38 +0700 (Tue, 18 Jul 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "AGFEO SmartHome Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_agfeo_smarthome_detect.sc" );
	script_mandatory_keys( "agfeo_smarthome/detected" );
	script_tag( name: "summary", value: "AGFEO SmartHome is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "AGFEO SmartHome is prone to multiple vulnerabilities:

  - Unauthenticated access to web services and authentication bypass

  - Unauthenticated access to configuration ports

  - Hardcoded cryptographic keys

  - Multiple reflected cross site scripting (XSS) vulnerabilities" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "AGFEO SmartHome on ES 5/6/7 prior to version 1.12c" );
	script_tag( name: "solution", value: "Upgrade to version 1.12c or later." );
	script_xref( name: "URL", value: "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20170712-0_AGFEO_Smart_Home_Multiple_critical_vulnerabilities_v10.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.12c" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.12c" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

