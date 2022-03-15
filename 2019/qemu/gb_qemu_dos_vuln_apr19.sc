if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113381" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-02 12:52:59 +0000 (Thu, 02 May 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-14 20:29:00 +0000 (Tue, 14 May 2019)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-5008" );
	script_bugtraq_id( 108024 );
	script_name( "QEMU <= 3.1.50 Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_qemu_detect_lin.sc" );
	script_mandatory_keys( "QEMU/Lin/Ver" );
	script_tag( name: "summary", value: "QEMU is prone to a Denial of Service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "hw/sparc64/sun4u.c is vulnerable to a NULL pointer dereference, which allows
  an attacker to cause a denial of service via a device driver." );
	script_tag( name: "affected", value: "QEMU through version 3.1.50." );
	script_tag( name: "solution", value: "Update to version 4.0.0." );
	script_xref( name: "URL", value: "https://fakhrizulkifli.github.io/posts/2019/01/03/CVE-2019-5008/" );
	script_xref( name: "URL", value: "https://git.qemu.org/?p=qemu.git;a=history;f=hw/sparc64/sun4u.c;hb=HEAD" );
	exit( 0 );
}
CPE = "cpe:/a:qemu:qemu";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
location = infos["location"];
version = infos["version"];
if(version_is_less( version: version, test_version: "4.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.0", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

