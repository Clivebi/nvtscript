CPE = "cpe:/a:ibm:tivoli_endpoint_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105129" );
	script_bugtraq_id( 67899 );
	script_cve_id( "CVE-2014-0224" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_name( "IBM Endpoint Manager 9.1 OpenSSL Man in the Middle Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21677842" );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow attackers to obtain
sensitive information by conducting a man-in-the-middle attack. This may lead to other attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An OpenSSL advisory was announced on June 5, 2014 in several versions
of OpenSSL. Several vulnerabilities were detailed in this advisory. One affects IBM Endpoint Manager 9.1 --
the ChangeCipherSpec (CCS) Injection Vulnerability. This vulnerability can be exploited by a Man-in-the-middle
(MITM) attack allowing an attacker to eavesdrop and make falsifications between Root Server, Web Reports, Relay,
and Proxy Agent communications. An eavesdropping attacker can obtain console login credentials." );
	script_tag( name: "solution", value: "Upgrade all components to version 9.1.1117." );
	script_tag( name: "summary", value: "There is an OpenSSL vulnerability that could allow an attacker to decrypt
and modify traffic from a vulnerable client and server." );
	script_tag( name: "affected", value: "IBM Endpoint Manager 9.1 (9.1.1065, 9.1.1082, and 9.1.1088) are the only
affected versions. Previous versions are not affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2014-12-03 13:45:19 +0100 (Wed, 03 Dec 2014)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_ibm_endpoint_manager_web_detect.sc" );
	script_require_ports( "Services/www", 52311 );
	script_mandatory_keys( "ibm_endpoint_manager/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!IsMatchRegexp( version, "^9\\.1\\.[0-9]+" )){
	exit( 0 );
}
fixed_version = "9.1.1117";
cv = split( buffer: version, sep: ".", keep: FALSE );
ck_version = cv[2];
if(int( ck_version ) < int( 1117 )){
	report = "Installed version: " + version + "\nFixed version:     " + fixed_version + "\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

