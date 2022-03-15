CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141896" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-01-18 16:44:12 +0700 (Fri, 18 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-16 14:12:00 +0000 (Tue, 16 Apr 2019)" );
	script_cve_id( "CVE-2018-20555" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "WordPress Social Network Tabs Plugin Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "The WordPress Plugin Social Network Tabs, made by the company Design Chemical,
is leaking twice the Twitter access_token, access_token_secret, consumer_key and consumer_secret of their user
which is leading to a takeover of their Twitter account." );
	script_tag( name: "vuldetect", value: "Tries to read the Twitter secrets." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/fs0c131y/CVE-2018-20555" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "social-network-tabs/inc/dcwp_twitter.php" )){
	if(ContainsString( res, "\"access_token: \"" ) || ContainsString( res, "access_token_secret: \"" ) || ContainsString( res, "consumer_key: \"" ) || ContainsString( res, "consumer_secret: \"" )){
		report = "It was possible to read the twitter secrets in the source code of " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

