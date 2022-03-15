CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142629" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-19 07:32:21 +0000 (Fri, 19 Jul 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-11 20:54:00 +0000 (Tue, 11 Dec 2018)" );
	script_cve_id( "CVE-2018-19131" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Proxy Cache Security Update Advisory SQUID-2018:4" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to a cross-site scripting vulnerability to incorrect input
  handling when generating HTTPS response messages about TLS errors." );
	script_tag( name: "insight", value: "This problem allows a malicious HTTPS server to trigger error page delivery to
  a client and also inject arbitrary HTML code into the resulting error response.

  This problem is limited to Squid built with TLS / SSL support." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Squid versions 3.1.12.1 - 3.1.23, 3.2.0.4 - 3.5.28 and 4.x - 4.3." );
	script_tag( name: "solution", value: "Update to version 4.4 or later." );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2018_4.txt" );
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
if(version_in_range( version: version, test_version: "3.1.12.1", test_version2: "3.1.23" ) || version_in_range( version: version, test_version: "3.2.0.4", test_version2: "3.25.28" ) || version_in_range( version: version, test_version: "4.0", test_version2: "4.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

