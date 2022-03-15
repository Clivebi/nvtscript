CPE = "cpe:/a:elastic:elasticsearch";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108448" );
	script_version( "2021-09-29T05:25:13+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-07-04 15:46:03 +0200 (Wed, 04 Jul 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Elasticsearch Public WAN (Internet) / Public LAN Accessible" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elastic_elasticsearch_detect_http.sc", "global_settings.sc" );
	script_mandatory_keys( "elastic/elasticsearch/noauth", "keys/is_public_addr" );
	script_xref( name: "URL", value: "https://duo.com/blog/beyond-s3-exposed-resources-on-aws" );
	script_tag( name: "summary", value: "The script checks if the target host is running an Elasticsearch
  service accessible from a public WAN (Internet) / public LAN." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Evaluate if the target host is running an Elasticsearch
  service accessible from a public WAN (Internet) / public LAN.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)" );
	script_tag( name: "solution", value: "Only allow access to the Elasticsearch service from trusted
  sources or enable authentication via the X-Pack Elastic Stack extension." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("host_details.inc.sc");
require("network_func.inc.sc");
if(!is_public_addr()){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_kb_item( "elastic/elasticsearch/" + port + "/noauth" )){
	exit( 99 );
}
get_app_location( cpe: CPE, port: port, nofork: TRUE );
security_message( port: port );
exit( 0 );

