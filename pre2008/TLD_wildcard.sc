if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11840" );
	script_version( "2020-06-15T10:33:37+0000" );
	script_tag( name: "last_modification", value: "2020-06-15 10:33:37 +0000 (Mon, 15 Jun 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Exclude toplevel domain wildcard host" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2003 by Michel Arboi" );
	script_family( "Settings" );
	script_dependencies( "global_settings.sc" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "summary", value: "The host you were trying to scan is blacklisted: its address is known to
  be returned by a wildcard on some top level domains, or it's the openvas.org web server.

  You probably mistyped its name." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
excluded["64.94.110.11"] = 1;
excluded["64.55.105.9"] = 1;
excluded["212.181.91.6"] = 1;
excluded["195.20.32.83"] = 1;
excluded["195.20.32.86"] = 1;
excluded["206.253.214.102"] = 1;
excluded["202.128.12.163"] = 1;
excluded["194.205.62.122"] = 1;
excluded["219.88.106.80"] = 1;
excluded["195.7.77.20"] = 1;
excluded["203.119.4.6"] = 1;
excluded["194.205.62.62"] = 1;
excluded["194.205.62.42"] = 1;
excluded["216.35.187.246"] = 1;
excluded["216.98.141.250"] = 1;
excluded["65.125.231.178"] = 1;
excluded["146.101.245.154"] = 1;
excluded["194.205.62.102"] = 1;
excluded["202.128.12.162"] = 1;
excluded["217.115.203.20"] = 1;
excluded["62.129.131.34"] = 1;
excluded["62.23.61.4"] = 1;
excluded["69.20.61.189"] = 1;
excluded["203.119.12.43"] = 1;
excluded["206.241.31.20"] = 1;
excluded["206.241.31.21"] = 1;
excluded["206.241.31.22"] = 1;
excluded["206.241.31.23"] = 1;
excluded["206.241.31.24"] = 1;
excluded["206.241.31.25"] = 1;
excluded["206.241.31.26"] = 1;
excluded["206.241.31.27"] = 1;
excluded["206.241.31.28"] = 1;
excluded["66.240.11.100"] = 1;
excluded["66.240.11.101"] = 1;
excluded["66.240.11.102"] = 1;
excluded["66.240.11.103"] = 1;
excluded["66.240.11.104"] = 1;
excluded["66.240.11.105"] = 1;
excluded["66.240.11.106"] = 1;
excluded["66.240.11.107"] = 1;
excluded["66.240.11.108"] = 1;
excluded["66.240.11.109"] = 1;
excluded["66.240.11.110"] = 1;
excluded["63.105.37.100"] = 1;
excluded["63.105.37.101"] = 1;
excluded["63.105.37.102"] = 1;
excluded["63.105.37.103"] = 1;
excluded["63.105.37.104"] = 1;
excluded["63.105.37.105"] = 1;
excluded["63.105.37.106"] = 1;
excluded["63.105.37.107"] = 1;
excluded["63.105.37.108"] = 1;
excluded["63.105.37.109"] = 1;
excluded["63.105.37.110"] = 1;
target = get_host_ip();
if(excluded[target]){
	log_message( port: 0, data: target + " is in IP blacklist." );
	set_kb_item( name: "Host/dead", value: TRUE );
	exit( 0 );
}
exit( 0 );

