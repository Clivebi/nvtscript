if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12241" );
	script_version( "2021-10-01T13:17:20+0000" );
	script_tag( name: "last_modification", value: "2021-10-01 13:17:20 +0000 (Fri, 01 Oct 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Do not print on AppSocket and socketAPI printers" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2005 by Laurent Facq" );
	script_family( "Settings" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc", "nmap_mac.sc", "global_settings.sc" );
	script_add_preference( name: "Exclude PJL printer ports from scan", type: "entry", value: "2000,2501,9100,9101,9102,9103,9104,9105,9106,9107,9112,9113,9114,9115,9116,9200,10001", id: 1 );
	script_tag( name: "summary", value: "The host seems to be an AppSocket or socketAPI printer. Scanning
  it will waste paper. So ports 2000, 2501, 9100-9107, 9112-9116, 9200 and 10001 won't be scanned by
  default." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
if(get_kb_item( "Host/scanned" ) == 0){
	exit( 0 );
}
require("host_details.inc.sc");
require("ftp_func.inc.sc");
require("telnet_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("dump.inc.sc");
require("mac_prefix.inc.sc");
require("hp_printers.inc.sc");
require("sharp_printers.inc.sc");
require("kyocera_printers.inc.sc");
require("lexmark_printers.inc.sc");
require("xerox_printers.inc.sc");
require("ricoh_printers.inc.sc");
require("toshiba_printers.inc.sc");
require("epson_printers.inc.sc");
require("snmp_func.inc.sc");
require("pcl_pjl.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
pjl_ports_list = make_list();
func check_pjl_port_list( list ){
	var list, ports, port;
	if(!list){
		return FALSE;
	}
	ports = split( buffer: list, sep: ",", keep: FALSE );
	for port in ports {
		if(!ereg( pattern: "^[0-9]{1,5}$", string: port )){
			return FALSE;
		}
		if(int( port ) > 65535){
			return FALSE;
		}
	}
	return TRUE;
}
func report( data ){
	var data, port;
	pcl_pjl_register_all_ports( ports: pjl_ports_list );
	if(!invalid_list){
		for port in pjl_ports_list {
			if(get_port_state( port )){
				log_message( port: port, data: "This port was excluded from the scan to avoid printing out paper on this printer during a scan." );
			}
		}
	}
	log_message( port: 0, data: "Exclusion reason:\n\n" + data );
	set_kb_item( name: "Host/is_printer/reason", value: data );
	set_kb_item( name: "Host/is_printer", value: TRUE );
	exit( 0 );
}
is_printer = FALSE;
pjl_ports = script_get_preference( name: "Exclude PJL printer ports from scan", id: 1 );
pjl_default_ports_string = pcl_pjl_get_default_ports_string();
if( strlen( pjl_ports ) > 0 ){
	pjl_ports = str_replace( string: pjl_ports, find: " ", replace: "" );
	if( !check_pjl_port_list( list: pjl_ports ) ){
		report = "\"Exclude PJL printer ports from scan\" has wrong format or contains an invalid port and was ignored. Please use a\ncomma separated list of ports without spaces. Example: " + pjl_default_ports_string + "\n\n";
		report += "The following default ports were excluded from the scan to avoid printing out paper on this printer during a scan:\n\n" + pjl_default_ports_string;
		invalid_list = TRUE;
		log_message( port: 0, data: report );
		pjl_ports_list = pcl_pjl_get_default_ports();
	}
	else {
		pjl_report = pjl_ports;
		ports = split( buffer: pjl_ports, sep: ",", keep: FALSE );
		for port in ports {
			pjl_ports_list = make_list( pjl_ports_list,
				 port );
		}
	}
}
else {
	pjl_report = pjl_default_ports_string;
	pjl_ports_list = pcl_pjl_get_default_ports();
}
port = 161;
if(sysdesc = snmp_get_sysdescr( port: port )){
	if(ContainsString( sysdesc, "Xerox WorkCentre" ) || ContainsString( sysdesc, "XEROX DocuCentre" ) || ContainsString( sysdesc, "XEROX DocuPrint" ) || ContainsString( sysdesc, "XEROX Document Centre" ) || ContainsString( sysdesc, "Xerox Phaser" )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^Canon[^/]+/P" ) || ContainsString( sysdesc, "Canon LBP" )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^KYOCERA" ) && ContainsString( sysdesc, "Print" )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^Lexmark.*version.*kernel" )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^SHARP (MX|AR)" )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^RICOH" ) && ContainsString( sysdesc, "RICOH Network Printer" )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^TOSHIBA e-STUDIO" )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^SATO " )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^KONICA MINOLTA " )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^EPSON " )){
		is_printer = TRUE;
	}
	if(IsMatchRegexp( sysdesc, "^Fiery " )){
		is_printer = TRUE;
	}
}
if(is_printer){
	report( data: "Detected from SNMP sysDescr OID on port " + port + "/udp:\n\n" + sysdesc );
}
port = 9101;
if(get_udp_port_state( port )){
	soc = open_sock_udp( port );
	send( socket: soc, data: "\r\n" );
	r = recv( socket: soc, length: 512 );
	close( soc );
	if(r){
		is_printer = TRUE;
	}
}
if(is_printer){
	report( data: "Detected UDP AppSocket on port " + port + "/udp" );
}
port = 9100;
if(get_port_state( port )){
	vt_strings = get_vt_strings();
	pcl_pjl_reqs = pcl_pjl_get_detect_requests( vt_strings: vt_strings );
	for pcl_pjl_req in keys( pcl_pjl_reqs ) {
		soc = open_sock_tcp( port );
		if(!soc){
			continue;
		}
		response_check = pcl_pjl_reqs[pcl_pjl_req];
		send( socket: soc, data: pcl_pjl_req );
		r = recv( socket: soc, length: 512 );
		se = socket_get_error( soc );
		close( soc );
		if(( r && ContainsString( r, response_check ) ) || ( !r && se == ETIMEDOUT )){
			is_printer = TRUE;
			break;
		}
	}
}
if(is_printer){
	report( data: "Detected Printer Job Language (PJL) / Printer Command Language (PCL) service on port " + port + "/tcp" );
}
port = 21;
if(get_port_state( port )){
	banner = ftp_get_banner( port: port );
	if( ContainsString( banner, "JD FTP Server Ready" ) ){
		is_printer = TRUE;
	}
	else {
		if( ContainsString( banner, "220 Dell Laser Printer " ) ){
			is_printer = TRUE;
		}
		else {
			if( ContainsString( banner, "220 RICOH" ) ){
				is_printer = TRUE;
			}
			else {
				if( ContainsString( banner, "220 FTP print service" ) ){
					is_printer = TRUE;
				}
				else {
					if( ContainsString( banner, "220 KONICA MINOLTA" ) ){
						is_printer = TRUE;
					}
					else {
						if( ContainsString( banner, "220 Xerox" ) ){
							is_printer = TRUE;
						}
						else {
							if( ContainsString( banner, "FUJI XEROX" ) ){
								is_printer = TRUE;
							}
							else {
								if( ContainsString( banner, "Lexmark" ) ){
									is_printer = TRUE;
								}
								else {
									if( ContainsString( banner, "TOSHIBA e-STUDIO" ) ){
										is_printer = TRUE;
									}
									else {
										if( ContainsString( banner, " FTP server " ) && ContainsString( banner, "(OEM FTPD version" ) ){
											is_printer = TRUE;
										}
										else {
											if(ContainsString( banner, "EFI FTP Print server" )){
												is_printer = TRUE;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
if(is_printer){
	report( data: "Detected FTP banner on port " + port + "/tcp:\n\n" + banner );
}
port = 23;
if(get_port_state( port )){
	banner = telnet_get_banner( port: port );
	if( ContainsString( banner, "HP JetDirect" ) ){
		is_printer = TRUE;
	}
	else {
		if( ContainsString( banner, "RICOH Maintenance Shell." ) ){
			is_printer = TRUE;
		}
		else {
			if(ContainsString( banner, "Welcome. Type <return>, enter password at # prompt" )){
				is_printer = TRUE;
			}
		}
	}
}
if(is_printer){
	report( data: "Detected Telnet banner on port " + port + "/tcp:\n\n" + banner );
}
port = 79;
if(get_port_state( port )){
	soc = open_sock_tcp( port );
	if(soc){
		send( socket: soc, data: raw_string( 0x0d, 0x0a ) );
		banner = recv( socket: soc, length: 512, timeout: 5 );
		close( soc );
		if(banner && ( ContainsString( banner, "Printer Type: " ) || ContainsString( banner, "Print Job Status: " ) || ContainsString( banner, "Printer Status: " ) )){
			is_printer = TRUE;
		}
	}
}
if(is_printer){
	report( data: "Detected Finger banner on port " + port + "/tcp:\n\n" + banner );
}
port = 2002;
if(get_port_state( port )){
	soc = open_sock_tcp( port );
	if(soc){
		banner = recv( socket: soc, length: 23 );
		close( soc );
		if(banner && ContainsString( banner, "Please enter a password" )){
			is_printer = TRUE;
		}
	}
}
if(is_printer){
	report( data: "Detected Xerox DocuPrint banner on port " + port + "/tcp:\n\n" + banner );
}
if(mac = get_kb_item( "Host/mac_address" )){
	if(is_printer_mac( mac: mac )){
		is_printer = TRUE;
	}
}
if(is_printer){
	report( data: "Detected MAC-Address of a Printer-Vendor: " + mac );
}
konica_detect_urls = make_array();
konica_detect_urls["/wcd/top.xml"] = "^HTTP/1\\.[01] 301 Movprm";
konica_detect_urls["/wcd/system_device.xml"] = "^HTTP/1\\.[01] 301 Movprm";
konica_detect_urls["/wcd/system.xml"] = "^HTTP/1\\.[01] 301 Movprm";
ports = make_list( 80,
	 8000,
	 280,
	 631 );
for port in ports {
	if(!get_port_state( port )){
		continue;
	}
	buf = http_get_cache( item: "/", port: port );
	if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "Extend-sharp-setting-status" ) || ContainsString( buf, "Server: Rapid Logic" ) )){
		urls = get_sharp_detect_urls();
		for url in keys( urls ) {
			pattern = urls[url];
			url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
			buf = http_get_cache( item: url, port: port );
			if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
				continue;
			}
			if(eregmatch( pattern: pattern, string: buf, icase: TRUE )){
				is_printer = TRUE;
				reason = "Sharp Banner/Text on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
				break;
			}
		}
	}
	url = "/index.html";
	buf = http_get_cache( item: url, port: port );
	if(( ContainsString( buf, ">Canon" ) && ContainsString( buf, ">Copyright CANON INC" ) && ContainsString( buf, "Printer" ) ) || ContainsString( banner, "CANON HTTP Server" )){
		is_printer = TRUE;
		reason = "Canon Banner/Text on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		break;
	}
	url = "/";
	buf = http_get_cache( item: url, port: port );
	if(( ContainsString( buf, "erver: Catwalk" ) && ContainsString( buf, "com.canon.meap.service" ) ) || ( ( ( ContainsString( buf, "canonlogo.gif\" alt=\"CANON\"" ) ) || ( ContainsString( buf, "canonlogo.gif\" alt=" ) ) || ( ContainsString( buf, "canonlogo.gif" ) && ContainsString( buf, "Series</title>" ) ) ) && ContainsString( buf, ">Copyright CANON INC" ) )){
		is_printer = TRUE;
		reason = "Canon Banner/Text on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		break;
	}
	url = "/general/information.html?kind=item";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "<title>Brother HL.*series</title>" ) && IsMatchRegexp( buf, "Copyright.*Brother Industries" )){
		is_printer = TRUE;
		reason = "Brother Banner/Text on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		break;
	}
	url = "/WebConfig/";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "<title>SATO Printer Setup</title>" )){
		is_printer = TRUE;
		reason = "SATO Banner/Text on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		break;
	}
	for url in keys( konica_detect_urls ) {
		pattern = konica_detect_urls[url];
		buf = http_get_cache( item: url, port: port );
		if(!buf){
			continue;
		}
		if(eregmatch( pattern: pattern, string: buf, icase: TRUE )){
			is_printer = TRUE;
			reason = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			break;
		}
	}
	if(is_printer){
		break;
	}
	urls = get_hp_detect_urls();
	for url in keys( urls ) {
		pattern = urls[url];
		url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
		buf = http_get_cache( item: url, port: port );
		if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		if(eregmatch( pattern: pattern, string: buf, icase: TRUE )){
			is_printer = TRUE;
			reason = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			break;
		}
	}
	if(is_printer){
		break;
	}
	urls = get_ky_detect_urls();
	for url in keys( urls ) {
		pattern = urls[url];
		url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
		buf = http_get_cache( item: url, port: port );
		if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		if(eregmatch( pattern: pattern, string: buf, icase: TRUE )){
			is_printer = TRUE;
			reason = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			break;
		}
	}
	if(is_printer){
		break;
	}
	urls = get_lexmark_detect_urls();
	for url in keys( urls ) {
		pattern = urls[url];
		url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
		buf = http_get_cache( item: url, port: port );
		if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		if(eregmatch( pattern: pattern, string: buf, icase: TRUE )){
			is_printer = TRUE;
			reason = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			break;
		}
	}
	if(is_printer){
		break;
	}
	urls = get_xerox_detect_urls();
	for url in keys( urls ) {
		pattern = urls[url];
		url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
		buf = http_get_cache( item: url, port: port );
		if(!buf || ( !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && !IsMatchRegexp( buf, "^HTTP/1\\.[01] 401" ) )){
			continue;
		}
		buf = bin2string( ddata: buf, noprint_replacement: "" );
		if(eregmatch( pattern: pattern, string: buf, icase: TRUE )){
			is_printer = TRUE;
			reason = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			break;
		}
		if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 401" ) && ContainsString( buf, "CentreWare Internet Services" )){
			is_printer = TRUE;
			reason = "Found pattern: CentreWare Internet Services on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			break;
		}
	}
	if(is_printer){
		break;
	}
	urls = get_ricoh_detect_urls();
	for url in keys( urls ) {
		pattern = urls[url];
		url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
		buf = http_get_cache( item: url, port: port );
		if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		if(eregmatch( pattern: pattern, string: buf, icase: TRUE )){
			is_printer = TRUE;
			reason = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			break;
		}
	}
	if(is_printer){
		break;
	}
	urls = get_toshiba_detect_urls();
	for url in keys( urls ) {
		pattern = urls[url];
		url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
		buf = http_get_cache( item: url, port: port );
		if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		if(eregmatch( pattern: pattern, string: buf, icase: TRUE )){
			is_printer = TRUE;
			reason = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			break;
		}
	}
	url = "/wt4/home";
	res = http_get_cache( port: port, item: url );
	if( ContainsString( res, "<title>WebTools" ) && ContainsString( res, "id-footer-efi-logo" ) ){
		is_printer = TRUE;
		reason = "EFI Fiery Banner/Text on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	else {
		url = "/wt2parser.cgi?home_en";
		res = http_get_cache( port: port, item: url );
		if(ContainsString( res, "<title>Webtools" ) && ContainsString( res, "<span class=\"footertext\">&copy; EFI" ) && ContainsString( res, "wt2parser.cgi?status_en.htm" )){
			is_printer = TRUE;
			reason = "EFI Fiery Banner/Text on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
	if(is_printer){
		break;
	}
	res = http_get_remote_headers( port: port );
	if( !egrep( pattern: "SERVER\\s*:\\s*EPSON_Linux", string: res, icase: TRUE ) && !egrep( pattern: "Epson UPnP SDK", string: res, icase: TRUE ) && !egrep( pattern: "Server\\s*:\\s*EPSON HTTP Server", string: res, icase: TRUE ) && !egrep( pattern: "Server\\s*:\\s*EPSON-HTTP", string: res, icase: TRUE ) ){
		urls = get_epson_detect_urls();
		for url in keys( urls ) {
			pattern = urls[url];
			url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
			buf = http_get_cache( item: url, port: port );
			if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
				continue;
			}
			if(eregmatch( pattern: pattern, string: buf, icase: TRUE )){
				is_printer = TRUE;
				reason = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
				break;
			}
		}
	}
	else {
		is_printer = TRUE;
		reason = "Epson banner: " + res;
		break;
	}
	for url in make_list( "/",
		 "/main.asp",
		 "/index.asp",
		 "/index.html",
		 "/index.htm",
		 "/default.html" ) {
		buf = http_get_cache( item: url, port: port );
		if( ContainsString( banner, "Dell Laser Printer " ) || ContainsString( banner, "Server: EWS-NIC5/" ) || ContainsString( banner, "Dell Laser MFP " ) ){
			is_printer = TRUE;
			reason = "Dell Banner on port " + port + "/tcp: " + banner;
			break;
		}
		else {
			if( banner && ContainsString( banner, "Server: GoAhead-Webs" ) && ContainsString( banner, "Aficio SP" ) || ContainsString( banner, "<title>Web Image Monitor</title>" ) ){
				is_printer = TRUE;
				reason = "Printer Banner on port " + port + "/tcp: " + banner;
				break;
			}
			else {
				if( ContainsString( buf, "<title>Hewlett Packard</title>" ) || egrep( pattern: "<title>.*LaserJet.*</title>", string: buf, icase: TRUE ) || ContainsString( buf, "HP Officejet" ) || ContainsString( tolower( buf ), "server: hp-chai" ) || ( ContainsString( buf, "Server: Virata-EmWeb/" ) && ( ContainsString( banner, "HP" ) || ContainsString( buf, "printer" ) ) ) ){
					is_printer = TRUE;
					reason = "HP Banner/Text on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
					break;
				}
				else {
					if(ContainsString( buf, "Server: Xerox_MicroServer/Xerox" ) || ContainsString( buf, "Server: EWS-NIC" ) || ContainsString( buf, "<title>DocuPrint" ) || ContainsString( buf, "<title>Phaser" ) || ( ContainsString( buf, "XEROX WORKCENTRE" ) && ContainsString( buf, "Xerox Corporation. All Rights Reserved." ) ) || ( ContainsString( buf, "DocuCentre" ) && ContainsString( buf, "Fuji Xerox Co., Ltd." ) )){
						is_printer = TRUE;
						reason = "Xerox Banner/Text on URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
						break;
					}
				}
			}
		}
	}
	if(is_printer){
		break;
	}
}
if(is_printer){
	report( data: reason );
}
exit( 0 );

