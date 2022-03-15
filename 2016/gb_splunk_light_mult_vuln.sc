CPE = "cpe:/a:splunk:light";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106267" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-19 11:58:34 +0700 (Mon, 19 Sep 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2176", "CVE-2016-1541", "CVE-2015-2304", "CVE-2013-0211", "CVE-2016-4858", "CVE-2016-4857" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Splunk Light Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_splunk_light_detect.sc" );
	script_mandatory_keys( "SplunkLight/installed" );
	script_tag( name: "summary", value: "Splunk Light is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Splunk Light is affected by multiple vulnerabilities:

Multiple OpenSSL vulnerabilities (CVE-2016-2105, CVE-2016-2106, CVE-2016-2107, CVE-2016-2108, CVE-2016-2109,
CVE-2016-2176).

Multiple vulnerabilities in libarchive (CVE-2016-1541, CVE-2015-2304, CVE-2013-0211).

Open redirect vulnerability (CVE-2016-4857).

Cross-site scripting vulnerability (CVE-2016-4858)." );
	script_tag( name: "affected", value: "Splunk Light before 6.4.2" );
	script_tag( name: "solution", value: "Update to version 6.4.2 or later." );
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
if(version_is_less( version: version, test_version: "6.4.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.4.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

