CPE = "cpe:/a:eyes_of_network:eyes_of_network";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145463" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-01 02:45:24 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-26 20:04:00 +0000 (Fri, 26 Feb 2021)" );
	script_cve_id( "CVE-2021-27513", "CVE-2021-27514" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "Eyes Of Network (EON) <= 5.3-10 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_eyesofnetwork_detect.sc" );
	script_mandatory_keys( "eyesofnetwork/detected" );
	script_tag( name: "summary", value: "Eyes Of Network (EON) is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Authenticated arbitrary .xml.php file upload. (CVE-2021-27513)

  - SessionID prediction which might be leveraged for brute-force authentication bypass. (CVE-2021-27514)" );
	script_tag( name: "affected", value: "Eyes Of Network version 5.3-10 and prior." );
	script_tag( name: "solution", value: "No known solution is available as of 01st March, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://github.com/EyesOfNetworkCommunity/eonweb/issues/87" );
	script_xref( name: "URL", value: "https://github.com/ArianeBlow/exploit-eyesofnetwork5.3.10/blob/main/PoC-BruteForceID-arbitraty-file-upload-RCE-PrivEsc.py" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "5.3.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

