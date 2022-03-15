if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107807" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-22 12:08:23 +0200 (Wed, 22 Apr 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-31 06:15:00 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-10938" );
	script_name( "GraphicsMagick < 1.3.35 heap-based Buffer Overflow vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "os_detection.sc", "gb_graphicsmagick_detect_win.sc" );
	script_mandatory_keys( "Host/runs_windows", "GraphicsMagick/Win/Installed" );
	script_tag( name: "summary", value: "GraphicsMagick is prone to an integer overflow and resultant heap-based
  buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "GraphicsMagick has an integer overflow and resultant heap-based buffer
  overflow in HuffmanDecodeImage in magick/compress.c." );
	script_tag( name: "impact", value: "An attacker attempting to abuse a buffer overflow for a more specific
  purpose other than crashing the target system, can purposely overwrite important values in the call stack
  of the target machine such as the instruction pointer (IP) or base pointer (BP) in order to execute his or
  her potentially malicious unsigned code." );
	script_tag( name: "affected", value: "GraphicsMagick prior to version 1.3.35." );
	script_tag( name: "solution", value: "Update to GraphicsMagick version 1.3.35 or later." );
	script_xref( name: "URL", value: "https://sourceforge.net/p/graphicsmagick/code/ci/5b4dd7c6674140a115ec9424c8d19c6a458fac3e/" );
	exit( 0 );
}
CPE = "cpe:/a:graphicsmagick:graphicsmagick";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "1.3.35" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.35", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

