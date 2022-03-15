func get_hp_detect_urls(  ){
	var hp_detect_urls;
	hp_detect_urls = make_array();
	hp_detect_urls["/info_deviceStatus.html"] = "<title>HP (LaserJet [^ ]+) Series";
	hp_detect_urls["/hp/device/"] = "<title> HP Color i(LaserJet [^\n ]+)";
	hp_detect_urls["/info_deviceStatus.html?tab=Status"] = "<title>HP Color (LaserJet [^&]+)";
	hp_detect_urls["/info_deviceStatus.html?"] = "<title>HP (LaserJet [^&]+)";
	hp_detect_urls["/index_top.htm"] = NASLString( "(HP (LaserJet [^\\n ]+)|HP Color (LaserJet [^\\n ]+)|(DesignJet [^ ]+)|(psc [^ ]+) series)" );
	hp_detect_urls["/index.htm?cat=info&page=printerInfo"] = NASLString( "((Officejet Pro [^& ]+)|(Officejet [^\\n ]+))" );
	hp_detect_urls["/hp/device/InternalPages/Index?id=ConfigurationPage"] = "<strong id=\"ProductName\">HP ?([^&<]+)";
	hp_detect_urls["/"] = "<strong class=\"product\">HP ?([^&<]+)";
	hp_detect_urls["/hp/jetdirect/index.html"] = "<h1>HP (Latex [0-9]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml"] = "<dd:MakeAndModel>HP (PageWide Pro [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup1--#"] = "<dd:MakeAndModel>HP (PageWide [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup2--#"] = "<dd:MakeAndModel>(Deskjet [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup3--#"] = "<dd:MakeAndModel>(Envy [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup4--#"] = "<dd:MakeAndModel>(Ink Tank [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup5--#"] = "<dd:MakeAndModel>(Photosmart [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup6--#"] = "<dd:MakeAndModel>HP (Smart Tank [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup7--#"] = "<dd:MakeAndModel>(Smart Tank [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup8--#"] = "<dd:MakeAndModel>HP (OfficeJet [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup8--#"] = "<dd:MakeAndModel>(OfficeJet [^<]+)";
	hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup9--#"] = "<dd:MakeAndModel>HP ((Color )?Laser [^<]+)";
	return hp_detect_urls;
}
func check_hp_default_login( model, port ){
	var model, port, HP, host, req, buf;
	HP = hp_login_details( model: model );
	if(!HP){
		return FALSE;
	}
	if(HP["no_default_auth"]){
		if(HP["req_type"] == "GET"){
			if(HP["req_auth"] == "BASIC"){
				host = http_host_name( port: port );
				req = NASLString( "GET ", HP["login_url"], " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n" );
				buf = http_send_recv( port: port, data: req + "\r\n", bodyonly: FALSE );
				hp_error_exit( buf: buf );
				if(ContainsString( buf, HP["http_status"] )){
					if(eregmatch( pattern: HP["login_success"], string: buf )){
						return 2;
					}
				}
			}
		}
	}
}
func hp_login_details( model ){
	var model, hp_printer;
	hp_printer = make_array();
	if( model == "LaserJet 100 colorMFP M175nw" || model == "LaserJet P2015" || model == "LaserJet CP2025n" || model == "LaserJet CP1515n" || model == "LaserJet M1522nf MFP" || model == "LaserJet M1536dnf MFP" || model == "LaserJet M2727nf MFP" || model == "LaserJet 2605dtn" || model == "LaserJet 2605dn" || model == "LaserJet 3055" || model == "LaserJet CM1312nfi" || model == "LaserJet CM2320fxi" || model == "LaserJet CM1415fn" || model == "LaserJet CM2320nf" || model == "LaserJet 400 color M451dn" || model == "LaserJet 400 M401n" || model == "LaserJet 400 M401dn" ){
		hp_printer["req_type"] = "GET";
		hp_printer["login_url"] = "/set_config_networkIP.html";
		hp_printer["req_auth"] = "BASIC";
		hp_printer["no_default_auth"] = "TRUE";
		hp_printer["http_status"] = "HTTP/1.1 200";
		hp_printer["login_success"] = "label for=\"IPAddr1\">";
		return hp_printer;
	}
	else {
		if( model == "LaserJet 2840" ){
			hp_printer["req_type"] = "GET";
			hp_printer["login_url"] = "/hp/device/set_config_networkIP.html";
			hp_printer["req_auth"] = "BASIC";
			hp_printer["no_default_auth"] = "TRUE";
			hp_printer["http_status"] = "HTTP/1.1 200";
			hp_printer["login_success"] = "This table contains the Network IP heading";
			return hp_printer;
		}
		else {
			if( model == "LaserJet 5100" || model == "LaserJet 5000" || model == "LaserJet 4000" || model == "LaserJet 4050" || model == "LaserJet 3800" || model == "LaserJet 3700" || model == "LaserJet 3600" || model == "LaserJet 3500" || model == "LaserJet 2200" || model == "LaserJet 3550" || model == "LaserJet 3030" || model == "LaserJet 2300" || model == "LaserJet 8150" || model == "LaserJet 5800" || model == "Designjet 800PS" || model == "DesignJet 800" || model == "LaserJet 2550" || model == "LaserJet 1320" || model == "Designjet 500" || model == "DesignJet 1055CM" ){
				hp_printer["req_type"] = "GET";
				hp_printer["login_url"] = "/tcp_param.htm";
				hp_printer["req_auth"] = "BASIC";
				hp_printer["no_default_auth"] = "TRUE";
				hp_printer["http_status"] = "HTTP/1.1 200";
				hp_printer["login_success"] = "This table displays the TCP/IP configuration items";
				return hp_printer;
			}
			else {
				if( model == "LaserJet 4250" || model == "LaserJet 4600" || model == "LaserJet 4650" || model == "designjet 5500ps" || model == "LaserJet 4200" || model == "LaserJet 4730mfp" || model == "LaserJet 4730" || model == "LaserJet CM4730" || model == "LaserJet P2055dn" || model == "Color LaserJet M651" || model == "LaserJet 2430" ){
					hp_printer["req_type"] = "GET";
					hp_printer["login_url"] = "/hp/jetdirect/tcp_param.htm";
					hp_printer["req_auth"] = "BASIC";
					hp_printer["no_default_auth"] = "TRUE";
					hp_printer["http_status"] = "HTTP/1.1 200";
					hp_printer["login_success"] = "This table displays the TCP/IP configuration items";
					return hp_printer;
				}
				else {
					if( model == "psc 2500" ){
						hp_printer["req_type"] = "GET";
						hp_printer["login_url"] = "/uvl_gen_settings.htm";
						hp_printer["req_auth"] = "BASIC";
						hp_printer["no_default_auth"] = "TRUE";
						hp_printer["http_status"] = "HTTP/1.1 200";
						hp_printer["login_success"] = "This table is used to display the network protocol links/tabs";
						return hp_printer;
					}
					else {
						if( model == "Officejet Pro K5400" || model == "Officejet Pro K5400" || model == "Officejet Pro L7600" || model == "Officejet Pro 8500" || model == "Officejet 7000 E809a" ){
							hp_printer["req_type"] = "GET";
							hp_printer["login_url"] = "/index.htm?cat=network&page=wiredIfc&adaptorID=0";
							hp_printer["req_auth"] = "BASIC";
							hp_printer["no_default_auth"] = "TRUE";
							hp_printer["http_status"] = "HTTP/1.1 200";
							hp_printer["login_success"] = "id=\"alt_dnsserver1\"";
							return hp_printer;
						}
						else {
							if( model == "Officejet 4500" ){
								hp_printer["req_type"] = "GET";
								hp_printer["login_url"] = "/index.htm?cat=network&page=wirelessIfc";
								hp_printer["req_auth"] = "BASIC";
								hp_printer["no_default_auth"] = "TRUE";
								hp_printer["http_status"] = "HTTP/1.1 200";
								hp_printer["login_success"] = "id=\"alt_dnsserver1\"";
								return hp_printer;
							}
							else {
								if(model == "Officejet Pro 8600"){
									hp_printer["req_type"] = "GET";
									hp_printer["login_url"] = "/webApps/Wired/ipV4.htf";
									hp_printer["req_auth"] = "BASIC";
									hp_printer["no_default_auth"] = "TRUE";
									hp_printer["http_status"] = "HTTP/1.1 200";
									hp_printer["login_success"] = "<?hp te.includeSubPage";
									return hp_printer;
								}
							}
						}
					}
				}
			}
		}
	}
}
func hp_error_exit( buf ){
	var buf;
	if(!buf || ereg( pattern: "HTTP/1.(0|1) (404|401|500)", string: buf )){
		exit( 0 );
	}
	return TRUE;
}

