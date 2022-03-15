CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803744" );
	script_version( "2021-03-01T08:21:56+0000" );
	script_cve_id( "CVE-2012-0031" );
	script_bugtraq_id( 51407 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2013-08-21 19:53:07 +0530 (Wed, 21 Aug 2013)" );
	script_name( "Apache HTTP Server Scoreboard Security Bypass Vulnerability (Windows)" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to Apache HTTP Server 2.2.22 or later." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'inscoreboard.c', certain type field within
  a scoreboard shared memory segment leading to an invalid call to the free function." );
	script_tag( name: "affected", value: "Apache HTTP Server version before 2.2.22." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to bypass certain security
  restrictions. Other attacks are also possible." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://svn.apache.org/viewvc?view=revision&revision=1230065" );
	script_xref( name: "URL", value: "http://www.halfdog.net/Security/2011/ApacheScoreboardInvalidFreeOnShutdown" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_windows" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "2.2.22" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.2.22", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

