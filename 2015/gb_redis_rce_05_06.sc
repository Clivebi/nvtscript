CPE = "cpe:/a:redis:redis";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105290" );
	script_cve_id( "CVE-2015-4335" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-04-22T08:55:01+0000" );
	script_name( "Redis EVAL Lua Sandbox Escape" );
	script_xref( name: "URL", value: "http://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-escape/" );
	script_tag( name: "impact", value: "Successfully attack may allow the attacker to execute code in the context of the application" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "It is possible to break out of the Lua sandbox in Redis and execute arbitrary code." );
	script_tag( name: "affected", value: "Redis < 2.8.21/3.0.2" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-04-22 08:55:01 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-06-05 16:01:37 +0200 (Fri, 05 Jun 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_redis_detect.sc" );
	script_require_ports( "Services/redis", 6379 );
	script_mandatory_keys( "redis/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_in_range( version: vers, test_version: "3.0", test_version2: "3.0.1" ) || version_in_range( version: vers, test_version: "2.8", test_version2: "2.8.20" )){
		report = "Installed version: " + vers + "\n" + "Fixed version:     3.0.2/2.8.21";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

