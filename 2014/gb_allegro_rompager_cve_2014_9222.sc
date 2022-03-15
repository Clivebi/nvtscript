CPE = "cpe:/a:allegrosoft:rompager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105154" );
	script_cve_id( "CVE-2014-9222" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "Allegro RomPager `Misfortune Cookie` Vulnerability" );
	script_xref( name: "URL", value: "http://mis.fortunecook.ie/" );
	script_xref( name: "URL", value: "http://mis.fortunecook.ie/too-many-cooks-exploiting-tr069_tal-oppenheim_31c3.pdf" );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request with a special crafted cookie and check the response." );
	script_tag( name: "solution", value: "Firmware update is available." );
	script_tag( name: "summary", value: "The remote Allegro RomPager service is vulnerable to the `Misfortune Cookie` Vulnerability." );
	script_tag( name: "affected", value: "RomPager services with versions before 4.34" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-12-23 10:22:44 +0100 (Tue, 23 Dec 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_allegro_rompager_detect.sc" );
	script_require_ports( "Services/www", 7547 );
	script_mandatory_keys( "allegro/rompager/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
vtstrings = get_vt_strings();
url = "/tr069";
rand = "/" + vtstrings["lowercase_rand"];
cookie = "C107373883=" + rand;
if(http_vuln_check( port: port, url: url, pattern: rand, extra_check: "was not found on the RomPager", cookie: cookie )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

