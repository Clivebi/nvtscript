CPE_PREFIX = "cpe:/o:d-link:dcs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144538" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-09-09 06:30:14 +0000 (Wed, 09 Sep 2020)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-11 20:40:00 +0000 (Fri, 11 Sep 2020)" );
	script_cve_id( "CVE-2020-25078", "CVE-2020-25079" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "D-Link DCS IP Cameras Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dcs_http_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_dcs_device" );
	script_tag( name: "summary", value: "Multiple D-Link DCS IP Cameras are prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Unauthenticated administrator password disclosure via /config/getuser (CVE-2020-25078)

  - Authenticated command injection via /cgi-bin/ddns_enc.cgi (CVE-2020-25079)" );
	script_tag( name: "affected", value: "D-Link DCS-2530L and DCS-2670L. Other models might be affected as well." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10180" );
	script_xref( name: "URL", value: "https://twitter.com/Dogonsecurity/status/1273251236167516161" );
	script_xref( name: "URL", value: "https://twitter.com/Dogonsecurity/status/1271265152118259712" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!get_app_location( cpe: cpe, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/config/getuser?index=0";
if(http_vuln_check( port: port, url: url, pattern: "pass=", check_header: TRUE, extra_check: "name=" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

