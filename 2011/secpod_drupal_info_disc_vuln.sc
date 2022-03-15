if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902574" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)" );
	script_cve_id( "CVE-2011-3730" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Drupal Information Disclosure Vulnerability" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "drupal/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "Drupal Version 7.0." );
	script_tag( name: "insight", value: "The flaw is due to insufficient error checking, allows remote
  attackers to obtain sensitive information via a direct request to a .php
  file, which reveals the installation path in an error message." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Drupal and is prone to information disclosure
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/!_README" );
	script_xref( name: "URL", value: "http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/drupal-7.0" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "drupal" )){
	exit( 0 );
}
url = dir + "/modules/simpletest/tests/upgrade/drupal-6.upload.database.php";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<b>Fatal error</b>: .*Call to undefined function .*db_insert\\(\\) in .*drupal-6\\.upload\\.database\\.php" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
}

