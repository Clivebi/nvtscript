CPE = "cpe:/a:php:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807554" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-04-25 11:53:15 +0530 (Mon, 25 Apr 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "PHPmongoDB CSRF And XSS Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with PHPmongoDB
  and is prone to multiple cross site scripting and cross site request forgery
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due,

  - The multiple cross-site request forgery (CSRF) vulnerabilities in the
    index.php script which can be exploited via different vectors.

  - An insufficient validation of user-supplied input via GET parameters
    'URL', 'collection', 'db' and POST parameter 'collection' in index.php
    script and other parameters may be also affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session, and to
  conduct request forgery attacks." );
	script_tag( name: "affected", value: "PHPmongoDB version 1.0.0" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/136686" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpmongodb_remote_detect.sc" );
	script_mandatory_keys( "PHPmongoDB/Installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!mongoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!mongodir = get_app_location( cpe: CPE, port: mongoPort )){
	exit( 0 );
}
if(mongodir == "/"){
	mongodir = "";
}
mongourl = mongodir + "/index.php/\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: mongoPort, url: mongourl, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: make_list( "content=\"mongoDB",
	 "PHPmongoDB.org",
	 ">Sign In" ) )){
	report = http_report_vuln_url( port: mongoPort, url: mongourl );
	security_message( port: mongoPort, data: report );
	exit( 0 );
}

