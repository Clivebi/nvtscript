CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804144" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2013-6129" );
	script_bugtraq_id( 62909 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2013-11-15 12:55:00 +0530 (Fri, 15 Nov 2013)" );
	script_name( "Vbulletin Authentication Bypass Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "vbulletin_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "vbulletin/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to bypass security
  restrictions." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it
  is able to bypass authentication." );
	script_tag( name: "insight", value: "The flaw is due to the 'upgrade.php' script which does not require
  authentication, which allows to create administrative accounts via
  the customerid, htmldata[password], htmldata[confirmpassword], and
  htmldata[email] parameters." );
	script_tag( name: "solution", value: "Upgrade to version 4.2.2 or 5.0.5 or later." );
	script_tag( name: "summary", value: "This host is running vBulletin and is prone to security bypass vulnerability." );
	script_tag( name: "affected", value: "vBulletin version 4.1.x and 5.x.x are affected." );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/123811" );
	script_xref( name: "URL", value: "http://www.net-security.org/secworld.php?id=15743" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
for dir2 in make_list( "",
	 "/core" ) {
	url = dir + dir2 + "/install/upgrade.php";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "vBulletin" ) && ContainsString( res, "Customer Number<" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

