CPE = "cpe:/a:idera:uptime_infrastructure_monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808235" );
	script_version( "$Revision: 12986 $" );
	script_cve_id( "CVE-2015-8268" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-09 08:58:52 +0100 (Wed, 09 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-27 17:28:12 +0530 (Mon, 27 Jun 2016)" );
	script_name( "Idera Up.time Agent Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_uptime_infrastructure_monitor_remote_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Idera/Uptime/Infrastructure/Monitor/Installed", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "https://vuldb.com/?id.87807" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/204232" );
	script_tag( name: "summary", value: "This host is installed with Idera Up.time
  Agent and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unauthenticated access
  to remote file system that the uptime.agent has read access to." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to read arbitrary files from a system running the Up.time agent for
  Linux." );
	script_tag( name: "affected", value: "Up.time agent versions 7.5 and 7.6
  on Linux" );
	script_tag( name: "solution", value: "Upgrade to Up.time agent 7.7 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "7.5" ) || version_is_equal( version: vers, test_version: "7.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

