CPE = "cpe:/a:python:python";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118193" );
	script_version( "2021-09-21T14:01:15+0000" );
	script_tag( name: "last_modification", value: "2021-09-21 14:01:15 +0000 (Tue, 21 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-11 10:50:32 +0200 (Sat, 11 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-03 15:33:00 +0000 (Wed, 03 Feb 2021)" );
	script_cve_id( "CVE-2020-14422" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Python < 3.5.10, 3.6.x < 3.6.12, 3.7.x < 3.7.9, 3.8.x < 3.8.4 Python Issue (bpo-41004) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_python_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "python/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Python is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Lib/ipaddress.py improperly computes hash values in the IPv4Interface
  and IPv6Interface classes, which might allow a remote attacker to cause a denial of service if an
  application is affected by the performance of a dictionary containing IPv4Interface or IPv6Interface
  objects, and this attacker can cause many dictionary entries to be created." );
	script_tag( name: "affected", value: "Python prior to version 3.5.10, versions 3.6.x prior to 3.6.12,
  3.7.x prior to 3.7.9 and 3.8.x prior to 3.8.4." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_xref( name: "URL", value: "https://python-security.readthedocs.io/vuln/ipaddress-hash-collisions.html" );
	script_xref( name: "Advisory-ID", value: "bpo-41004" );
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
location = infos["location"];
if(version_is_less( version: version, test_version: "3.5.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.5.10", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.7.0", test_version2: "3.7.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.7.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.8.0", test_version2: "3.8.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.8.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

