if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800952" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3528" );
	script_name( "MyMsg 'profile.php' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35753" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9105" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51635" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_mymsg_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "al4us/mymsg/detected" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause SQL Injection
  attack to gain and delete sensitive information about the database used by the web application." );
	script_tag( name: "affected", value: "MyMsg version 1.0.3 and prior on all platforms." );
	script_tag( name: "insight", value: "The flaw is due to error in 'Profile.php' file. The user supplied
  data passed into the 'uid' parameter in 'Profile.php' is not properly sanitised
  before being used in SQL queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with MyMsg and is prone to SQL Injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
mymsgPort = http_get_port( default: 80 );
mymsgVer = get_kb_item( "www/" + mymsgPort + "/MyMsg" );
mymsgVer = eregmatch( pattern: "^(.+) under (/.*)$", string: mymsgVer );
if(mymsgVer[1] != NULL){
	if(version_is_less_equal( version: mymsgVer[1], test_version: "1.0.3" )){
		security_message( mymsgPort );
	}
}

