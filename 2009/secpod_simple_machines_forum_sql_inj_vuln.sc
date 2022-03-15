if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900544" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-6741" );
	script_bugtraq_id( 29734 );
	script_name( "Simple Machines Forum SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/5826" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/43118" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_simple_machines_forum_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "SMF/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code,
  and can view, add, modify or delete information in the back-end database." );
	script_tag( name: "affected", value: "Simple Machines Forum 1.1.4 and prior." );
	script_tag( name: "insight", value: "Error exists while sending a specially crafted SQL statements into load.php
  when setting the db_character_set parameter to a multibyte character which
  causes the addslashes PHP function to generate a \\(backslash) sequence that
  does not quote the '(single quote) character, as demonstrated via a manlabels
  action to index.php." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Simple Machines Forum and is prone
  to SQL Injection Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
httpPort = http_get_port( default: 80 );
ver = get_kb_item( "www/" + httpPort + "/SMF" );
ver = eregmatch( pattern: "^(.+) under (/.*)$", string: ver );
if(ver[1] == NULL){
	exit( 0 );
}
if(version_is_less_equal( version: ver[1], test_version: "1.1.4" )){
	security_message( httpPort );
}

