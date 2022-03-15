CPE = "cpe:/a:thekelleys:dnsmasq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112682" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-01-08 08:53:00 +0000 (Wed, 08 Jan 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)" );
	script_cve_id( "CVE-2019-14834" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dnsmasq < 2.81 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_dnsmasq_consolidation.sc" );
	script_mandatory_keys( "thekelleys/dnsmasq/detected" );
	script_tag( name: "summary", value: "Dnsmasq is prone to a Denial of Service (DoS)
  vulnerability." );
	script_tag( name: "impact", value: "The memory leak allows remote attackers to cause a
  DoS (memory consumption) via vectors involving DHCP response creation." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "affected", value: "Dnsmasq prior to 2.81." );
	script_tag( name: "solution", value: "Update to version 2.81 or later." );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-14834" );
	script_xref( name: "URL", value: "http://thekelleys.org.uk/dnsmasq/CHANGELOG" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.81" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.81", install_path: location );
	security_message( port: port, proto: proto, data: report );
	exit( 0 );
}
exit( 99 );

