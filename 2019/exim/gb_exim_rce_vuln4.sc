CPE = "cpe:/a:exim:exim";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108654" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-07-29 06:24:44 +0000 (Mon, 29 Jul 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_cve_id( "CVE-2019-16928" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Exim 4.92 < 4.92.3 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_exim_detect.sc" );
	script_mandatory_keys( "exim/installed" );
	script_tag( name: "summary", value: "Exim is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There is a heap-based buffer overflow in string_vformat (string.c).
  The currently known exploit uses an extraordinary long EHLO string to crash the Exim process that is
  receiving the message. While at this mode of operation Exim already dropped its privileges, other
  paths to reach the vulnerable code may exist." );
	script_tag( name: "impact", value: "A local or remote attacker can execute programs." );
	script_tag( name: "affected", value: "Exim version 4.92 up to and including 4.92.2." );
	script_tag( name: "solution", value: "Update to version 4.92.3 or later." );
	script_xref( name: "URL", value: "https://exim.org/static/doc/security/CVE-2019-16928.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.92", test_version2: "4.92.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.92.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

