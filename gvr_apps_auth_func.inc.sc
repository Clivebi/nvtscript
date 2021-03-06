func get_typo3_login_cookie( cinstall, tport, chost ){
	var cinstall, tport, chost, url, treq, tres, username, password, challenge;
	var payload, tcookie, PHPSESSID, cCookie, req, buf, rcookie;
	url = cinstall + "/typo3/index.php";
	treq = http_get( item: NASLString( url ), port: tport );
	tres = http_keepalive_send_recv( port: tport, data: treq, bodyonly: FALSE );
	username = urlencode( str: get_kb_item( "http/login" ) );
	password = urlencode( str: get_kb_item( "http/password" ) );
	challenge = eregmatch( pattern: "name=\"challenge\" value=\"([a-z0-9]+)\"", string: tres );
	if(challenge){
		password = hexstr( MD5( password ) );
		userident = hexstr( MD5( username + ":" + password + ":" + challenge[1] ) );
		payload = "login_status=login&username=" + username + "&p_field=&commandLI=Log+In&" + "userident=" + userident + "&challenge=" + challenge[1] + "&redirect_url=" + "alt_main.php&loginRefresh=&interface=backend";
		tcookie = eregmatch( pattern: "(be_typo_user=[a-z0-9]+\\;)", string: tres );
		PHPSESSID = eregmatch( pattern: "(PHPSESSID=[a-z0-9]+\\;?)", string: tres );
		if(!PHPSESSID[1]){
			PHPSESSID[1] = "PHPSESSID=37dh7b4vkprsui40hmg3hf4716";
		}
		if(tcookie[1] && PHPSESSID[1]){
			cCookie = tcookie[1] + " showRefMsg=false; " + PHPSESSID[1] + " typo3-login-cookiecheck=true";
			req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", chost, "\\r\\n", "User-Agent: ", http_get_user_agent(), "\\r\\n", "Referer: http://", chost, "/typo3/alt_menu.php\\r\\n", "Connection: keep-alive\\r\\n", "Cookie: ", cCookie, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( payload ), "\\r\\n\\r\\n", payload );
			buf = http_keepalive_send_recv( port: tport, data: req );
			rcookie = eregmatch( pattern: "(be_typo_user=[a-z0-9]+\\;)", string: buf );
			if( !rcookie[1] ){
				cookie = tcookie[1] + " " + PHPSESSID[1];
			}
			else {
				cookie = rcookie[1] + " showRefMsg=false; " + PHPSESSID[1] + " typo3-login-cookiecheck=true";
			}
			return cookie;
		}
	}
}
func get_typo3_logout( loc, lport, lhost, lcookie ){
	var loc, lport, lhost, lcookie, lurl, lreq, lres;
	lurl = loc + "/typo3/logout.php";
	lreq = NASLString( "GET ", lurl, " HTTP/1.1\\r\\n", "Host: ", lhost, "\\r\\n", "User-Agent: ", http_get_user_agent(), "\\r\\n", "Referer: http://", lhost, "/typo3/alt_menu.php\\r\\n", "Connection: keep-alive\\r\\n", "Cookie: ", lcookie, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n\\r\\n" );
	lres = http_keepalive_send_recv( port: lport, data: lreq, bodyonly: FALSE );
}

