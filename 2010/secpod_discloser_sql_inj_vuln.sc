if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902138" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)" );
	script_cve_id( "CVE-2009-4719" );
	script_bugtraq_id( 35923 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Discloser 'more' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9349" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/505478/100/0/threaded" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_discloser_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "discloser/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow execution of arbitrary SQL
  commands in the affected application." );
	script_tag( name: "affected", value: "Discloser version 0.0.4 rc2." );
	script_tag( name: "insight", value: "The flaw is due to input validation error in the 'index.php'
  script when processing the 'more' parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Discloser and is prone to SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
discport = http_get_port( default: 80 );
discver = get_kb_item( "www/" + discport + "/Discloser" );
if(isnull( discver )){
	exit( 0 );
}
discver = eregmatch( pattern: "^(.+) under (/.*)$", string: discver );
if(!isnull( discver[1] )){
	if(version_is_equal( version: discver[1], test_version: "0.0.4.rc2" )){
		security_message( discport );
	}
}

