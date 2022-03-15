CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106484" );
	script_version( "2019-05-10T14:24:23+0000" );
	script_tag( name: "last_modification", value: "2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2016-12-19 14:15:02 +0700 (Mon, 19 Dec 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2016-10003" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Information Disclosure Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "squid_proxy_server/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Squid is prone an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Due to incorrect comparison of request headers Squid can deliver responses
containing private data to clients it should not have reached." );
	script_tag( name: "impact", value: "This problem allows a remote attacker to discover private and sensitive
information about another clients browsing session. Potentially including credentials which allow access to
further sensitive resources.

This problem only affects Squid configured to use the Collapsed Forwarding feature." );
	script_tag( name: "affected", value: "Squid 3.5.x 4.0.x on Windows." );
	script_tag( name: "solution", value: "Upgrade to 3.5.23, 4.0.17 or later." );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2016_10.txt" );
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
if(version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.22" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.5.23" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.17" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

