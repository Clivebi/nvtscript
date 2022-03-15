if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800929" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-7087" );
	script_bugtraq_id( 30264 );
	script_name( "OpenPro Remote File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/494426/100/0/threaded" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openpro_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "openpro/detected" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code by
  including remote PHP files via malicious URLs." );
	script_tag( name: "affected", value: "OpenPro version 1.3.1 and prior." );
	script_tag( name: "insight", value: "The user supplied input passed into 'LIBPATH' parameter in the
  'search_wA.php' script is not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with OpenPro and is prone to Remote File
  Inclusion vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
openPort = http_get_port( default: 80 );
openproVer = get_kb_item( "www/" + openPort + "/OpenPro" );
openproVer = eregmatch( pattern: "^(.+) under (/.*)$", string: openproVer );
if(openproVer[1] != NULL){
	if(version_is_less_equal( version: openproVer[1], test_version: "1.3.1" )){
		security_message( openPort );
	}
}

