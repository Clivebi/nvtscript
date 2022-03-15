if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113202" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-29 11:47:28 +0200 (Tue, 29 May 2018)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-29 18:51:00 +0000 (Fri, 29 Jun 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2018-11494", "CVE-2018-11495" );
	script_name( "Opencart <= 3.0.2.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "opencart_detect.sc" );
	script_mandatory_keys( "OpenCart/installed" );
	script_tag( name: "summary", value: "Opencart is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - OpenCart allows Directory Traversal in the editDownload function in admin\\model\\catalog\\download.php
    via admin/index.php?routecatalog/download/edit, related to the download_id.

  - The 'program extension upload' feature in OpenCart has a six-step process (upload, install, unzip, move, xml, remove)
    that allows attacker to execute arbitrary code if the remove step is skipped, because the attacker can discover
    a secret temporary directory name (containing 10 random digits) via the previously described Directory Traversal attack." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to gain complete control over the target system." );
	script_tag( name: "affected", value: "OpenCart through version 3.0.2.0." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.bigdiao.cc/2018/05/24/Opencart-v3-0-2-0/" );
	exit( 0 );
}
CPE = "cpe:/a:opencart:opencart";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "3.0.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

