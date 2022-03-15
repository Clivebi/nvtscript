if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800919" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2618" );
	script_bugtraq_id( 35495 );
	script_name( "MDPro Surveys Module SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9021" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51385" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_mdpro_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mdpro/detected" );
	script_tag( name: "impact", value: "This flaw can be exploited via malicious SQL commands to modify
  or delete information in the back-end database." );
	script_tag( name: "affected", value: "MDPro version 1.083.x" );
	script_tag( name: "insight", value: "The Surveys module fails to validate the user supplied data
  passed into the 'pollID' parameter before using it in an SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with MDPro and is prone to SQL Injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
mdproPort = http_get_port( default: 80 );
mdproVer = get_kb_item( "www/" + mdproPort + "/MDPro" );
mdproVer = eregmatch( pattern: "^(.+) under (/.*)$", string: mdproVer );
if(IsMatchRegexp( mdproVer[1], "^1\\.083" )){
	security_message( mdproPort );
}

