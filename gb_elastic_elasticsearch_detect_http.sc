if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105031" );
	script_version( "2021-08-12T14:07:30+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 14:07:30 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-05-22 15:00:02 +0200 (Thu, 22 May 2014)" );
	script_name( "Elastic Elasticsearch and Logstash Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9200 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Elastic Elasticsearch.

  Note: Once a Elasticsearch service was detected it is assumed that Logstash is
  installed in the same version (ELK Stack)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9200 );
buf = http_get_cache( item: "/", port: port, fetch404: TRUE );
if(!buf || !IsMatchRegexp( buf, "Content-Type\\s*:\\s*application/json" )){
	exit( 0 );
}
if(( ( ContainsString( buf, "build_hash" ) || ContainsString( buf, "build_timestamp" ) || ContainsString( buf, "build_date" ) ) && ContainsString( buf, "lucene_version" ) && ( ContainsString( buf, "elasticsearch" ) || ContainsString( buf, "You Know, for Search" ) ) ) || ( ContainsString( buf, "{\"ok\":false,\"message\":\"Unknown resource.\"}" ) && IsMatchRegexp( buf, "X-Cloud-Request-Id\\s*:.+" ) )){
	version = "unknown";
	install = "/";
	elastic_cpe = "cpe:/a:elastic:elasticsearch";
	logstash_cpe = "cpe:/a:elastic:logstash";
	elastic_cpe2 = "cpe:/a:elasticsearch:elasticsearch";
	logstash_cpe2 = "cpe:/a:elasticsearch:logstash";
	vers = eregmatch( string: buf, pattern: "number\" : \"([0-9a-z.]+)\",", icase: TRUE );
	if(!isnull( vers[1] )){
		version = chomp( vers[1] );
		elastic_cpe += ":" + version;
		logstash_cpe += ":" + version;
		elastic_cpe2 += ":" + version;
		logstash_cpe2 += ":" + version;
	}
	url = "/_cat/indices?v";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(ContainsString( buf, "health" ) || ContainsString( buf, "status" ) || ContainsString( buf, "index" )){
		extra = "Collected information (truncated) from " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " :\n\n";
		extra += substr( buf, 0, 1000 );
		set_kb_item( name: "elastic/elasticsearch/noauth", value: TRUE );
		set_kb_item( name: "elastic/elasticsearch/" + port + "/noauth", value: TRUE );
	}
	set_kb_item( name: "elastic/elasticsearch/detected", value: TRUE );
	set_kb_item( name: "elastic/logstash/detected", value: TRUE );
	register_product( cpe: elastic_cpe, location: install, port: port, service: "www" );
	register_product( cpe: logstash_cpe, location: install, port: 0, service: "www" );
	register_product( cpe: elastic_cpe2, location: install, port: port, service: "www" );
	register_product( cpe: logstash_cpe2, location: install, port: 0, service: "www" );
	report = build_detection_report( app: "Elastic Elasticsearch", version: version, install: install, cpe: elastic_cpe, extra: extra, concluded: vers[0] );
	report += "\n\n";
	report += build_detection_report( app: "Elastic Logstash", version: version, install: install, cpe: logstash_cpe, concluded: "Existence of Elasticsearch service, the actual version of the Logstash service might differ." );
	log_message( port: port, data: report );
}
exit( 0 );

