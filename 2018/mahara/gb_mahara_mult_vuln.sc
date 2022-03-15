if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112290" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-06-04 10:26:06 +0200 (Mon, 04 Jun 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-03 14:51:00 +0000 (Tue, 03 Jul 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-11195", "CVE-2018-11196" );
	script_name( "Mahara < 17.04.8, < 17.10.5, < 18.04.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mahara_detect.sc" );
	script_mandatory_keys( "mahara/detected" );
	script_tag( name: "summary", value: "Mahara is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mahara is prone to the following vulnerabilities:

  - Mahara is vulnerable to the browser 'back and refresh' attack. This allows malicious users with physical
    access to the web browser of a Mahara user, after they have logged in, to potentially gain access to their
    Mahara credentials. (CVE-2018-11195)

  - Mahara can be used as medium to transmit viruses by placing infected files into a Leap2A archive and uploading
    that to Mahara. In contrast to other ZIP files that are uploaded, ClamAV (when activated) does not check
    Leap2A archives for viruses, allowing malicious files to be available for download. While files cannot be
    executed on Mahara itself, Mahara can be used to transfer such files to user computers. (CVE-2018-11196)" );
	script_tag( name: "affected", value: "Mahara 17.04 before 17.04.8 and 17.10 before 17.10.5 and 18.04 before 18.04.1." );
	script_tag( name: "solution", value: "Update to Mahara 17.04.8, 17.10.5 or 18.04.1 respectively." );
	script_xref( name: "URL", value: "https://bugs.launchpad.net/mahara/+bug/1770561" );
	script_xref( name: "URL", value: "https://mahara.org/interaction/forum/topic.php?id=8269" );
	script_xref( name: "URL", value: "https://bugs.launchpad.net/mahara/+bug/1770535" );
	script_xref( name: "URL", value: "https://mahara.org/interaction/forum/topic.php?id=8270" );
	exit( 0 );
}
CPE = "cpe:/a:mahara:mahara";
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
if(version_is_equal( version: version, test_version: "18.04" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "18.04.1", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "17.04", test_version2: "17.04.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "17.04.8", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "17.10", test_version2: "17.10.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "17.10.5", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

