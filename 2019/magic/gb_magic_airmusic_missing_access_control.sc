CPE = "cpe:/a:magic:airmusic";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108651" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2019-13474" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-17 11:11:44 +0100 (Sun, 17 Mar 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Magic AirMusic Insufficient Access Control Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_magic_airmusic_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "magic/airmusic/detected" );
	script_xref( name: "URL", value: "https://www.vulnerability-db.com/?q=articles/2019/09/09/imperial-dabman-internet-radio-undocumented-telnetd-code-execution" );
	script_xref( name: "URL", value: "https://www.vulnerability-lab.com/get_content.php?id=2183" );
	script_xref( name: "URL", value: "https://seclists.org/fulldisclosure/2019/Sep/12" );
	script_tag( name: "summary", value: "Various products of multiple vendors using the Magic AirMusic web interface for
  the control of the device are prone to an insufficient access control vulnerability." );
	script_tag( name: "impact", value: "In the worst case a remote attacker could modify the system to spread remotly
  ransomware or other malformed malicious viruses / rootkits / destruktive scripts. He can aslso use the web-server
  to be part of an iot botnet." );
	script_tag( name: "affected", value: "TELESTAR Bobs Rock Radio, Dabman D10, Dabman i30 Stereo, Imperial i110, Imperial i150,
  Imperial i200, Imperial i200-cd, Imperial i400, Imperial i450, Imperial i500-bt, and Imperial i600 devices are known to be
  affected. Other devices and vendors might be affected as well." );
	script_tag( name: "solution", value: "According to the security researcher the vendor TELESTAR has released the firmware update
  TN81HH96-g102h-g103**a*-fb21a-3624 which is mitigating this vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check the response." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
for cmd in make_list( "playinfo",
	 "hotkeylist",
	 "stop" ) {
	url = dir + "/" + cmd;
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(ContainsString( res, "<result>OK</result>" ) || ContainsString( res, "<menu><item_total>" ) || ContainsString( res, "<result>FAIL</result>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

