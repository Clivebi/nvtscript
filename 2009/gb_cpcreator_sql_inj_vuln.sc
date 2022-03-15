if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801006" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3330" );
	script_name( "cP Creator 'tickets' Cookie SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36815" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9726" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_cpcreator_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cpcreator/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to conduct SQL
  injection attacks." );
	script_tag( name: "affected", value: "cP Creator Version 2.7.1 and prior." );
	script_tag( name: "insight", value: "Input passed to the 'tickets' cookie in index.php (if 'page' is
  set to 'support' and 'task' is set to 'ticket') is not properly sanitised before being used in SQL queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running cP Creator and is prone to SQL Injection
  Vulnerability" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
cpcreatPort = http_get_port( default: 80 );
cpcreatVer = get_kb_item( "www/" + cpcreatPort + "/cPCreator" );
if(!cpcreatVer){
	exit( 0 );
}
cpcreatVer = eregmatch( pattern: "^(.+) under (/.*)$", string: cpcreatVer );
if(cpcreatVer[1] != NULL){
	if(version_is_less_equal( version: cpcreatVer[1], test_version: "2.7.1" )){
		security_message( cpcreatPort );
	}
}

