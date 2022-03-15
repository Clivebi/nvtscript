if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801008" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3541" );
	script_name( "PHPGenealogie 'CoupleDB.php' Remote File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9155" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51728" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpgenealogie_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpgenealogie/detected" );
	script_tag( name: "affected", value: "PHPGenealogie version 2.0" );
	script_tag( name: "insight", value: "The flaw is due to error in 'DataDirectory' parameter in
  'CoupleDB.php' which is not properly verified before being used to includefiles." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running PHPGenealogie and is prone to Remote File
  Inclusion vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  code on the vulnerable Web server." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
phpgenPort = http_get_port( default: 80 );
phpgenVer = get_kb_item( "www/" + phpgenPort + "/PHPGenealogie" );
phpgenVer = eregmatch( pattern: "^(.+) under (/.*)$", string: phpgenVer );
if( ( phpgenVer[2] != NULL ) && ( !safe_checks() ) ){
	sndReq = http_get( item: NASLString( phpgenVer[2], "/CoupleDB.php?Parametre=0&" + "DataDirectory=xyz/VT-RemoteFileInclusion.txt" ), port: phpgenPort );
	rcvRes = http_send_recv( port: phpgenPort, data: sndReq );
	if(ContainsString( rcvRes, "xyz/VT-RemoteFileInclusion.txt" )){
		security_message( phpgenPort );
		exit( 0 );
	}
}
else {
	if(phpgenVer[1] != NULL){
		if(version_is_equal( version: phpgenVer[1], test_version: "2.0" )){
			security_message( phpgenPort );
		}
	}
}

