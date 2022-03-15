CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105257" );
	script_version( "2020-11-25T11:26:55+0000" );
	script_cve_id( "CVE-2015-1635" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-25 11:26:55 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-04-15 18:02:08 +0200 (Wed, 15 Apr 2015)" );
	script_name( "MS15-034 HTTP.sys Remote Code Execution Vulnerability (Active Check)" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "webmirror.sc", "secpod_ms_iis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3042553" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-034" );
	script_xref( name: "URL", value: "http://pastebin.com/ypURDPc4" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to run arbitrary
  code in the context of the current user and to perform actions in the security context of the current user." );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response" );
	script_tag( name: "insight", value: "Flaw exists due to the HTTP protocol stack 'HTTP.sys' that is triggered
  when parsing HTTP requests." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to Microsoft
  Bulletin MS15-034." );
	script_tag( name: "affected", value: "- Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
known_urls = http_get_kb_file_extensions( port: port, host: host, ext: "*" );
default_urls = make_list( "/",
	 "/welcome.png",
	 "/iis-85.png",
	 "/Iisstart.htm",
	 "/resources/logo.png",
	 "/favicon.ico" );
if( known_urls ) {
	files = make_list( default_urls,
		 known_urls );
}
else {
	files = default_urls;
}
checked = 0;
host = http_host_name( port: port );
for file in files {
	req = "GET " + file + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Range: bytes=0-18446744073709551615\r\n" + "\r\n";
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	checked++;
	if(ContainsString( buf, "Requested Range Not Satisfiable" )){
		security_message( port: port );
		exit( 0 );
	}
	if(ContainsString( buf, "request has an invalid header name" )){
		exit( 0 );
	}
	if(checked > 20){
		exit( 99 );
	}
}
exit( 99 );

