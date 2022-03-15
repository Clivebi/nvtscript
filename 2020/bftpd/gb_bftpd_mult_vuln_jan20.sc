if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113622" );
	script_version( "2021-08-31T13:35:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 13:35:08 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-01-13 11:58:30 +0000 (Mon, 13 Jan 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-21 18:15:00 +0000 (Tue, 21 Jan 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-6162", "CVE-2020-6835" );
	script_name( "Bftpd < 5.4 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "gb_bftpd_detect.sc" );
	script_mandatory_keys( "bftpd/detected" );
	script_tag( name: "summary", value: "Bftpd is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-6162: Under certain circumstances, an out-of-bounds read is triggered due to an
  uninitialized value. The daemon crashes at startup in the hidegroups_init function in dirlist.c.

  - CVE-2020-6835: There is a heap-based off-by-one error during file-transfer error-checking." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to crash the FTP
  server or execute arbitrary code on the target machine." );
	script_tag( name: "affected", value: "Bftdp through version 5.3." );
	script_tag( name: "solution", value: "Update to version 5.4." );
	script_xref( name: "URL", value: "http://bftpd.sourceforge.net/news.html#302460" );
	script_xref( name: "URL", value: "https://fossies.org/linux/bftpd/CHANGELOG" );
	exit( 0 );
}
CPE = "cpe:/a:bftpd:bftpd";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.4" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );
