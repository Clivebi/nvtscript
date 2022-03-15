if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105027" );
	script_cve_id( "CVE-2014-2084" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:C" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Skybox Security Appliance Multiple Information Disclosure Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/33327/" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-05-13 16:33:50 +0200 (Tue, 13 May 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 444 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "This would allow the malicious party to read system-related information
such as interface names, IP addresses and the appliance status." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request and check the response." );
	script_tag( name: "insight", value: "A vulnerability has been found in some Skybox View Appliances' Admin
interfaces which would allow a potential malicious party to bypass
the authentication mechanism and obtain read-only access to the
appliance's administrative menus." );
	script_tag( name: "solution", value: "Please refer to the vendor security advisor: Security Advisory 2014-3-25-1" );
	script_tag( name: "summary", value: "Skybox Security Appliance is prone to multiple information-disclosure vulnerabilities." );
	script_tag( name: "affected", value: "Skybox View Appliances with ISO versions: 6.3.33-2.14, 6.3.31-2.14,
6.4.42-2.54, 6.4.45-2.56, 6.4.46-2.57" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 444 );
if(buf = http_vuln_check( port: port, url: "/", pattern: "<title>SkyBox Web Administration", usecache: TRUE )){
	cookie = eregmatch( pattern: "Set-Cookie: ([^\r\n]+)", string: buf );
	if(!isnull( cookie[1] )){
		co = cookie[1];
	}
	urls = make_array( "/scripts/commands/getSystemInformation?_=111111111", "APPLIANCE_VERSION", "/scripts/commands/getNetworkConfigurationInfo", "HardwareAddress" );
	for url in keys( urls ) {
		if(http_vuln_check( port: port, url: url, pattern: urls[url], cookie: co )){
			security_message( port: port );
			exit( 0 );
		}
	}
	exit( 99 );
}
exit( 0 );

