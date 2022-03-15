if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142868" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2019-09-10 03:01:53 +0000 (Tue, 10 Sep 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Zyxel Gateway / Access Point External DNS Request Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zyxel_ap_http_detect.sc", "smtp_settings.sc" );
	script_mandatory_keys( "zyxel_ap/detected" );
	script_tag( name: "summary", value: "Some Zyxel Access Points are prone to an information disclosure vulnerability
  where external DNS requests can be made." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "A DNS request can be made by an unauthenticated attacker to either spam a DNS
  service of a third party with requests that have a spoofed origin or probe whether domain names are present on
  the internal network behind the firewall." );
	script_tag( name: "impact", value: "The vulnerability could allow an unauthenticated individual to spam an internal
  service or probe whether domain names are present on the internal network behind the firewall, which could
  result in internal DNS information disclosure." );
	script_tag( name: "affected", value: "Zyxel ATP200, ATP500, ATP800, UAG2100, UAG4100, USG20-VPN, USG20W-VPN, USG40,
  USG40W, USG60, USG60W, USG110, USG210, USG310, USG1100, USG1900, USG2200, VPN50, VPN100, VPN300, ZyWALL110,
  ZyWALL310, ZyWALL1100, NXC2500 and NXC5500." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://www.zyxel.com/support/web-CGI-vulnerability-of-gateways-and-access-point-controllers.shtml" );
	script_xref( name: "URL", value: "https://sec-consult.com/en/blog/advisories/external-dns-requests-in-zyxel-usg-uag-atp-vpn-nxc-series/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("smtp_func.inc.sc");
cpe_list = make_list( "cpe:/h:zyxel:atp100",
	 "cpe:/h:zyxel:atp500",
	 "cpe:/h:zyxel:atp800",
	 "cpe:/h:zyxel:uag2100",
	 "cpe:/h:zyxel:uag4100",
	 "cpe:/h:zyxel:usg20-vpn",
	 "cpe:/h:zyxel:usg20w-vpn",
	 "cpe:/h:zyxel:usg40",
	 "cpe:/h:zyxel:usg40w",
	 "cpe:/h:zyxel:usg60",
	 "cpe:/h:zyxel:usg60w",
	 "cpe:/h:zyxel:usg110",
	 "cpe:/h:zyxel:usg210",
	 "cpe:/h:zyxel:usg310",
	 "cpe:/h:zyxel:usg1100",
	 "cpe:/h:zyxel:usg1900",
	 "cpe:/h:zyxel:usg2200-vpn",
	 "cpe:/h:zyxel:vpn50",
	 "cpe:/h:zyxel:vpn100",
	 "cpe:/h:zyxel:vpn300",
	 "cpe:/h:zyxel:zywall110",
	 "cpe:/h:zyxel:zywall310",
	 "cpe:/h:zyxel:zywall1100",
	 "cpe:/h:zyxel:nxc2500",
	 "cpe:/h:zyxel:nxc5500" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list, service: "www" )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!get_app_location( cpe: cpe, port: port, nofork: TRUE )){
	exit( 0 );
}
domain = get_3rdparty_domain();
url = "/redirect.cgi?arip=" + domain;
if(http_vuln_check( port: port, url: url, pattern: "Set-Cookie: arip=[0-9.]+;" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

