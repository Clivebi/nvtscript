if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805472" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-0995", "CVE-2015-0994", "CVE-2015-0993", "CVE-2015-0992", "CVE-2015-0991", "CVE-2015-0976" );
	script_bugtraq_id( 73475, 73474, 73473, 73471, 73469, 73468 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-04-11 14:20:21 +0530 (Sat, 11 Apr 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Inductive Automation Ignition Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Inductive
  Automation Ignition and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether vulnerable version of Inductive Automation Ignition is
  installed or not." );
	script_tag( name: "insight", value: "Multiple errors exist due to:

  - The MD5 Message-Digest Algorithm does not provide enough collision resistance
    when hashing keys.

  - A flaw in Inductive Automation Ignition that is triggered when resetting the
    session ID parameter via a HTTP request.

  - A flaw in the web interface that is due to a missing session termination once
    a user logs out.

  - A flaw in application that is due to the program storing OPC server credentials
    in plaintext.

  - A flaw in application that is triggered when an unhandled exception occurs,
    which can cause an error or warning message.

  - The application does not validate input before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information, hijack an active
  session, bypass the anti-bruteforce mechanism, create malicious applications
  or conduct other spoofing attacks, and create a specially crafted request that
  would execute arbitrary script code in a user's browser session." );
	script_tag( name: "affected", value: "Inductive Automation Ignition version 7.7.2" );
	script_tag( name: "solution", value: "Upgrade to Inductive Automation Ignition
  version 7.7.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-15-090-01" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8088 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.inductiveautomation.com/downloads/ignition" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
http_port = http_get_port( default: 8088 );
req = http_get( item: "/main/web/status/", port: http_port );
buf = http_keepalive_send_recv( port: http_port, data: req, bodyonly: FALSE );
if("Server: Jetty" && IsMatchRegexp( buf, "HTTP/1.. 302 Found" )){
	cookie = eregmatch( pattern: "JSESSIONID=([0-9a-zA-Z]+);", string: buf );
	if(!cookie[1]){
		exit( 0 );
	}
	url = NASLString( "/main/web/status/;jsessionid=" ) + cookie[1] + "?0";
	req = http_get( item: url, port: http_port );
	buf = http_keepalive_send_recv( port: http_port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, ">Ignition Gateway<" ) && ContainsString( buf, ">Ignition by Inductive Automation" )){
		ignitionVer = eregmatch( pattern: ">Ignition Gateway.*detail..([0-9.]+) ", string: buf );
		if(ignitionVer[1]){
			if(version_is_equal( version: ignitionVer[1], test_version: "7.7.2" )){
				report = "Installed version: " + ignitionVer[1] + "\n" + "Fixed version:     " + "7.7.4" + "\n";
				security_message( data: report, port: http_port );
				exit( 0 );
			}
		}
	}
}

