CPE = "cpe:/a:redis:redis";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105291" );
	script_version( "$Revision: 10074 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-06-05 10:01:45 +0200 (Tue, 05 Jun 2018) $" );
	script_tag( name: "creation_date", value: "2015-06-05 15:48:46 +0200 (Fri, 05 Jun 2015)" );
	script_name( "Redis Server No Password" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_redis_detect.sc" );
	script_require_ports( "Services/redis", 6379 );
	script_mandatory_keys( "redis/no_password" );
	script_tag( name: "summary", value: "The remote Redis server is not protected with a password." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Evaluate if the remote Redis server is protected by a password." );
	script_tag( name: "insight", value: "It was possible to login without a password." );
	script_tag( name: "solution", value: "Set password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
get_app_location( cpe: CPE, port: port, nofork: TRUE );
if(!get_kb_item( "redis/" + port + "/no_password" )){
	exit( 99 );
}
security_message( port: port );
exit( 0 );

