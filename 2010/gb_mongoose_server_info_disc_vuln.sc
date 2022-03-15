CPE = "cpe:/a:cesanta:mongoose";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800412" );
	script_version( "2021-07-07T12:08:51+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 12:08:51 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2010-01-09 13:17:56 +0100 (Sat, 09 Jan 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-4530", "CVE-2009-4535" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Mongoose Web Server <= 2.8 Source Code Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_mongoose_web_server_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cesanta/mongoose/http/detected", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Mongoose Web Server is prone to a source code disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "The issue is due to an error within the handling of HTTP
  requests and can be exploited to disclose the source code of certain scripts (e.g. PHP) by
  appending '::$DATA' or '/' to a URI." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to display
  the source code of arbitrary files instead of an expected HTML response." );
	script_tag( name: "affected", value: "Mongoose Web Server version 2.8 and prior on Windows." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_xref( name: "URL", value: "http://freetexthost.com/0lcsrgt3vw" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36934" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/index.php::$DATA";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(!isnull( res ) && ContainsString( res, "<?php" ) && ContainsString( res, "?>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

