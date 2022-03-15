CPE = "cpe:/h:electroindustries_gaugetech:total_websolutions";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813629" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_cve_id( "CVE-2018-12921" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-31 11:56:00 +0000 (Fri, 31 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-07-04 11:28:37 +0530 (Wed, 04 Jul 2018)" );
	script_name( "Electro Industries GaugeTech Nexus series Products Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Electro
  Industries GaugeTech Nexus series Product and is prone to information disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check if response is disclosing sensitive information or not." );
	script_tag( name: "insight", value: "The flaw is due to improper input validation
  by the 'meter_information.htm', 'diag_system.htm' and 'diag_dnp_lan_wan.htm' URI's." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Electro Industries GaugeTech Nexus series
  Products." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "https://www.seebug.org/vuldb/ssvid-97371" );
	script_xref( name: "URL", value: "https://electroind.com/downloads/nexus-meters" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "gb_electro_industries_gaugetech_total_web_solutions_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ElectroIndustries/GaugeTech/TotalWebSolutions/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!elePort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: elePort )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/diag_dnp_lan_wan.htm";
#if(http_vuln_check( port: elePort, url: url, check_header: TRUE, pattern: "<title>DNP LAN/WAN Status</title>", "Electro Industries/GaugeTech", extra_check: make_list( "DNP TCP Connection",

if(http_vuln_check( port: elePort, url: url, check_header: TRUE, pattern: "<title>DNP LAN/WAN Status</title>", extra_check: make_list( "DNP TCP Connection",
	 "Mode:" ) )){
	report = http_report_vuln_url( port: elePort, url: url );
	security_message( port: elePort, data: report );
	exit( 0 );
}
exit( 99 );

