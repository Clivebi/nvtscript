CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142049" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-26 10:40:54 +0700 (Tue, 26 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 18:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_cve_id( "CVE-2019-9020", "CVE-2019-9021", "CVE-2019-9023", "CVE-2019-9024" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHP Multiple Vulnerabilities - Feb19 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PHP is prone to multiple vulnerabilities:

  - Invalid input to the function xmlrpc_decode() can lead to an invalid memory access (heap out of bounds read or
    read after free). This is related to xml_elem_parse_buf in ext/xmlrpc/libxmlrpc/xml_element.c. (CVE-2019-9020)

  - A heap-based buffer over-read in PHAR reading functions in the PHAR extension may allow an attacker to read
    allocated or unallocated memory past the actual data when trying to parse the file name. (CVE-2019-9021)

  - A number of heap-based buffer over-read instances are present in mbstring regular expression functions when
    supplied with invalid multibyte data. (CVE-2019-9023)

  - xmlrpc_decode() can allow a hostile XMLRPC server to cause PHP to read memory outside of allocated areas
    (CVE-2019-9024)" );
	script_tag( name: "affected", value: "PHP versions before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14 and
7.3.x before 7.3.1." );
	script_tag( name: "solution", value: "Update to version 5.6.40, 7.1.16, 7.2.14, 7.3.1 or later." );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77242" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77249" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77247" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77370" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77371" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77381" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77382" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77385" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77394" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77418" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77380" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "5.6.40" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.40", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.0", test_version2: "7.1.25" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.26", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.2", test_version2: "7.2.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.2.14", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "7.3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.3.1", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

