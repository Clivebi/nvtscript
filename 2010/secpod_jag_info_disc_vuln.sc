if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900745" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-0665" );
	script_name( "JAG (Just Another Guestbook) Information Disclosure Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_MIXED_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_jag_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "xs4all/jag/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to download the backup
  database and obtain sensitive information." );
	script_tag( name: "affected", value: "JAG (Just Another Guestbook) version 1.14 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper restrictions on the 'database.sql file'. By
  sending a direct request, this can exploited to download the backup database." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running JAG and is prone to Information Disclosure
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/56228" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/11406" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
jagPort = http_get_port( default: 80 );
jagVer = get_kb_item( "www/" + jagPort + "/JAG" );
if(isnull( jagVer )){
	exit( 0 );
}
jagVer = eregmatch( pattern: "^(.+) under (/.*)$", string: jagVer );
if(!safe_checks() && jagVer[2] != NULL){
	url = NASLString( jagVer[2], "/database.sql" );
	sndReq = http_get( item: url, port: jagPort );
	rcvRes = http_send_recv( port: jagPort, data: sndReq );
	if(!isnull( rcvRes ) && ( ContainsString( rcvRes, "create table guestbook" ) )){
		report = http_report_vuln_url( port: jagPort, url: url );
		security_message( port: jagPort, data: report );
		exit( 0 );
	}
}
if(jagVer[1] != NULL){
	if(version_is_less_equal( version: jagVer[1], test_version: "1.14" )){
		security_message( jagPort );
	}
}

