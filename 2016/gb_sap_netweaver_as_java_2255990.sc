require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106149" );
	script_version( "2021-04-27T06:08:28+0000" );
	script_tag( name: "last_modification", value: "2021-04-27 06:08:28 +0000 (Tue, 27 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-07-22 14:30:27 +0700 (Fri, 22 Jul 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2016-3973" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "SAP NetWeaver AS Java Information Disclosure Vulnerability (2255990)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_sap_netweaver_as_java_http_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_sap_netweaver_portal_http_detect.sc", "gsf/gb_sap_netweaver_as_http_detect.sc" );
	}
	script_mandatory_keys( "sap/netweaver/as/http/detected" );
	script_tag( name: "summary", value: "SAP NetWeaver Application Server (AS) Java is prone to an
  information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if WD_CHAT is accessible." );
	script_tag( name: "insight", value: "The chat feature in the Real-Time Collaboration (RTC) services
  allows remote attackers to obtain sensitive user information." );
	script_tag( name: "impact", value: "An unauthenticated attacker can get information about SAP
  NetWeaver AS Java users." );
	script_tag( name: "affected", value: "SAP NetWeaver AS Java version 7.10 (7.1) through 7.50 (7.5)." );
	script_tag( name: "solution", value: "See the referenced vendor advisories for a solution." );
	script_xref( name: "URL", value: "https://erpscan.io/advisories/erpscan-16-016-sap-netweaver-7-4-information-disclosure-wd_chat/" );
	script_xref( name: "URL", value: "https://launchpad.support.sap.com/#/notes/2255990" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
cpe_list = make_list( "cpe:/a:sap:netweaver_application_server_java",
	 "cpe:/a:sap:netweaver_portal",
	 "cpe:/a:sap:netweaver_as" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list, service: "www", first_cpe_only: TRUE )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!infos = get_app_version_and_location( cpe: cpe, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
version = infos["version"];
if(version && !IsMatchRegexp( version, "^7\\.[1-5]" )){
	exit( 0 );
}
dir = infos["location"];
if(dir == "/" || IsMatchRegexp( dir, "^[0-9]+/tcp$" )){
	dir = "";
}
url = dir + "/webdynpro/resources/sap.com/tc~rtc~coll.appl.rtc~wd_chat/Chat";
if(http_vuln_check( port: port, url: url, pattern: "set-cookie", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

