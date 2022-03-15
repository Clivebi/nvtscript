if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900551" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1670" );
	script_bugtraq_id( 34866 );
	script_name( "TCPDB Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34966" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50371" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tcpdb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "tcpdb/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to bypass
  security restrictions and add admin accounts, via unspecified vectors in user/index.php script." );
	script_tag( name: "affected", value: "TCPDB version 3.8 and prior." );
	script_tag( name: "insight", value: "The vulnerability is due to the application not properly
  restricting access to certain administrative pages. (e.g. 'user/index.php')" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with TCPDB and is prone to security
  bypass vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
tPort = http_get_port( default: 80 );
tcpdbVer = get_kb_item( "www/" + tPort + "/TCPDB" );
tcpdbVer = eregmatch( pattern: "^(.+) under (/.*)$", string: tcpdbVer );
if(tcpdbVer[1] != NULL){
	if(version_is_less_equal( version: tcpdbVer[1], test_version: "3.8" )){
		security_message( tPort );
	}
}

