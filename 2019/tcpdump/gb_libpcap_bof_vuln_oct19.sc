if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113544" );
	script_version( "2019-10-21T13:56:23+0000" );
	script_tag( name: "last_modification", value: "2019-10-21 13:56:23 +0000 (Mon, 21 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-10-21 15:50:34 +0000 (Mon, 21 Oct 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-16301" );
	script_name( "libpcap < 1.9.1 Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_tcpdump_ssh_detect.sc" );
	script_mandatory_keys( "libpcap/detected" );
	script_tag( name: "summary", value: "libpcap is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists because of errors in pcapng reading." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  execute arbitrary code on the target machine." );
	script_tag( name: "affected", value: "libpcap through version 1.9.0." );
	script_tag( name: "solution", value: "Update to version 1.9.1." );
	script_xref( name: "URL", value: "https://www.tcpdump.org/libpcap-changes.txt" );
	exit( 0 );
}
CPE = "cpe:/a:tcpdump:libpcap";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.9.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.9.1", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

