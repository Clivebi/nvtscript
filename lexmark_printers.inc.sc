func get_lexmark_detect_urls(  ){
	var lexmark_detect_urls;
	lexmark_detect_urls = make_array();
	lexmark_detect_urls["/"] = "<title>Lexmark ([^<]+)</title>";
	lexmark_detect_urls["/#--avoid-dup1--#"] = "<title>Lexmark&#032;([^<]+)</title>";
	return lexmark_detect_urls;
}
func check_lexmark_default_login( model, port ){
	var model, port, lex, host, req, buf;
	lex = lexmark_login_details( model: model );
	if(!lex){
		return FALSE;
	}
	if(lex["no_default_auth"]){
		if(lex["req_type"] == "GET"){
			if(lex["req_auth"] == "BASIC"){
				if( lex["headers"] ){
					req = http_get_req( port: port, url: lex["login_url"], add_headers: lex["headers"] );
					buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
				}
				else {
					req = http_get( port: port, item: lex["login_url"] );
					buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
				}
				lexmark_error_exit( buf: buf );
				if(ereg( pattern: lex["http_status"], string: buf )){
					if(eregmatch( pattern: lex["login_success"], string: buf )){
						return 2;
					}
				}
			}
		}
	}
}
func lexmark_login_details( model ){
	var model, lexmark_printer;
	lexmark_printer = make_array();
	if( model == "CS421dn" || model == "CS622de" || model == "CS923de" || model == "CX421adn" || model == "CX522ade" || model == "CX622ade" || model == "MS321dn" || model == "MS421dn" || model == "MS521dn" || model == "MS621dn" || model == "MS821n" || model == "MS821dn" || model == "MS823n" || model == "MS823dn" || model == "MS826de" || model == "MX321adn" || model == "MX421ade" || model == "MX622adhe" || model == "XC8160" ){
		lexmark_printer["req_type"] = "GET";
		lexmark_printer["login_url"] = "/webglue/content?c=%2FSettings%2FSecurity%2FEditSecuritySetups%2FInternalAccounts%2FManageInternalGroups&lang=en";
		lexmark_printer["req_auth"] = "BASIC";
		lexmark_printer["no_default_auth"] = "TRUE";
		lexmark_printer["headers"] = make_array( "X-Requested-With", "XMLHttpRequest" );
		lexmark_printer["http_status"] = "HTTP/1.. 200";
		lexmark_printer["login_success"] = "\nAdd Group\n";
		return lexmark_printer;
	}
	else {
		if( model == "T644" || model == "E450dn" || model == "T642" || model == "119" ){
			lexmark_printer["req_type"] = "GET";
			lexmark_printer["login_url"] = "/cgi-bin/dynamic/config/secure/changepass.html";
			lexmark_printer["req_auth"] = "BASIC";
			lexmark_printer["no_default_auth"] = "TRUE";
			lexmark_printer["http_status"] = "HTTP/1.. 200";
			lexmark_printer["login_success"] = "NAME=\"vac.255.GENPASSWORD\"";
			return lexmark_printer;
		}
		else {
			if( model == "T630" || model == "C510" || model == "T620" || model == "T522" || model == "T520" ){
				lexmark_printer["req_type"] = "GET";
				lexmark_printer["login_url"] = "/port_0/config/security";
				lexmark_printer["req_auth"] = "BASIC";
				lexmark_printer["no_default_auth"] = "TRUE";
				lexmark_printer["http_status"] = "HTTP/1.. 200";
				lexmark_printer["login_success"] = "NAME=\"GENPASSWORD\"";
				return lexmark_printer;
			}
			else {
				if( model == "X954" || model == "X952" || model == "X656de" || model == "X792" || model == "T650" || model == "X464de" || model == "C925" || model == "X463de" || model == "C734" || model == "E460dn" || model == "E462dtn" || model == "T652" || model == "C792" || model == "MX410de" || model == "MX910de" || model == "T654" || model == "C925" || model == "X746" || model == "C736" || model == "X738de" || model == "X864de" ){
					lexmark_printer["req_type"] = "GET";
					lexmark_printer["login_url"] = "/cgi-bin/dynamic/printer/config/secure/authsetup.html";
					lexmark_printer["req_auth"] = "BASIC";
					lexmark_printer["no_default_auth"] = "TRUE";
					lexmark_printer["http_status"] = "HTTP/1.. 200";
					lexmark_printer["login_success"] = "select name=\"auth_type\" id=\"auth_type\"";
					return lexmark_printer;
				}
				else {
					if( model == "CS310dn" || model == "CS317dn" || model == "CS410dn" || model == "CX310dn" || model == "CX317dn" || model == "CX410de" || model == "CX417de" || model == "CX510de" || model == "CX517de" || model == "MX310dn" || model == "MX317dn" || model == "MX410de" || model == "MX417de" || model == "MX510de" || model == "MX511de" || model == "MX517de" || model == "MX611de" || model == "MX617de" || model == "X860de" || model == "X864de" || model == "X950" || model == "x954" || model == "XC2132" || model == "XM1145" || model == "XM3150" || model == "XM5170" || model == "XM7155" || model == "XM7170" ){
						lexmark_printer["req_type"] = "GET";
						lexmark_printer["login_url"] = "/cgi-bin/dynamic/config/gen/changepass.html";
						lexmark_printer["req_auth"] = "BASIC";
						lexmark_printer["no_default_auth"] = "TRUE";
						lexmark_printer["http_status"] = "HTTP/1.. 200";
						lexmark_printer["login_success"] = ": 8( | )?-( )?128 ";
						return lexmark_printer;
					}
					else {
						if( model == "E260dn" || model == "X342n" || model == "X203n" || model == "X204n" || model == "C543" || model == "X364dn" || model == "E250dn" || model == "X264dn" || model == "S510 Series" || model == "C544" || model == "Pro5500 Series" || model == "E360dn" || model == "X543" || model == "S310 Series" || model == "X544" || model == "C540" ){
							lexmark_printer["req_type"] = "GET";
							lexmark_printer["login_url"] = "/cgi-bin/dynamic/config/gen/changepass.html";
							lexmark_printer["req_auth"] = "BASIC";
							lexmark_printer["no_default_auth"] = "TRUE";
							lexmark_printer["http_status"] = "HTTP/1.. 200";
							lexmark_printer["login_success"] = "NAME=\"vac.255.GENPASSWORD\"";
							return lexmark_printer;
						}
						else {
							if( model == "C935" || model == "X642e" || model == "C782" || model == "X945e" ){
								lexmark_printer["req_type"] = "GET";
								lexmark_printer["login_url"] = "/cgi-bin/dynamicpf/pf/config/gen/changepass.html";
								lexmark_printer["req_auth"] = "BASIC";
								lexmark_printer["no_default_auth"] = "TRUE";
								lexmark_printer["http_status"] = "HTTP/1.. 200";
								lexmark_printer["login_success"] = "NAME=\"vac.255.GENPASSWORD\"";
								return lexmark_printer;
							}
							else {
								if(model == "T656"){
									lexmark_printer["req_type"] = "GET";
									lexmark_printer["login_url"] = "/cgi-bin/dynamic/printer/config/secure/auth/backuppwd.html";
									lexmark_printer["req_auth"] = "BASIC";
									lexmark_printer["no_default_auth"] = "TRUE";
									lexmark_printer["http_status"] = "HTTP/1.. 200";
									lexmark_printer["login_success"] = "id=\"useFallbackPassword\"";
									return lexmark_printer;
								}
							}
						}
					}
				}
			}
		}
	}
}
func lexmark_error_exit( buf ){
	var buf;
	if(!buf || ereg( pattern: "HTTP/1.(0|1) (404|401|500)", string: buf )){
		exit( 0 );
	}
	return TRUE;
}

