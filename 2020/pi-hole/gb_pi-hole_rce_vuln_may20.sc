CPE = "cpe:/a:pi-hole:web";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143881" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-12 04:23:02 +0000 (Tue, 12 May 2020)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-27 18:15:00 +0000 (Wed, 27 May 2020)" );
	script_cve_id( "CVE-2020-11108", "CVE-2019-8331", "CVE-2020-12620" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Pi-hole Ad-Blocker < 5.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pi-hole_detect.sc" );
	script_mandatory_keys( "pi-hole/detected" );
	script_tag( name: "summary", value: "The Pi-hole Ad-Blocker is prone to an authenticated remote code execution (RCE)
  vulnerability in the web interface, two Cross-Site Scripting (XSS) vulnerabilities in the 3rdparty 'Bootstrap'
  library and a privilege escalation vulnerability." );
	script_tag( name: "insight", value: "The following flaws exist:

  - The Gravity updater in Pi-hole allows an authenticated adversary to upload arbitrary files. This can be abused for
  Remote Code Execution by writing to a PHP file in the web directory. (Also, it can be used in conjunction with the
  sudo rule for the www-data user to escalate privileges to root.) The code error is in gravity_DownloadBlocklistFromUrl
  in gravity.sh (CVE-2020-11108)

  - An XSS vulnerability in the tooltip and popover plugins of the 3rdpary library 'Bootstrap' was fixed by implementing
  a new HTML sanitizer (CVE-2019-8331)

  - An XSS vulnerability in the in Alert, Carousel, Collapse, Dropdown, Modal, and Tab components of the 3rdpary library
  'Bootstrap' was fixed

  - Privilege escalation vulnerability through command injection (CVE-2020-12620)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Pi-hole Ad-Blocker version 4.4 and prior." );
	script_tag( name: "solution", value: "Update to version 5.0 or later." );
	script_xref( name: "URL", value: "https://github.com/pi-hole/pi-hole/pull/3237" );
	script_xref( name: "URL", value: "https://github.com/pi-hole/AdminLTE/pull/1022" );
	script_xref( name: "URL", value: "https://frichetten.com/blog/cve-2020-11108-pihole-rce/" );
	script_xref( name: "URL", value: "https://0xpanic.github.io/2020/07/21/Pihole.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "5.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

