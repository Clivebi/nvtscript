if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113747" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-08-31 08:48:43 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 19:21:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-13825", "CVE-2020-13826" );
	script_name( "i-doit CMDB <= 1.14.2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_idoit_cmdb_detect.sc" );
	script_mandatory_keys( "idoit_cmdb/detected" );
	script_tag( name: "summary", value: "i-doit CMDB is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Cross-site scripting (XSS) via
    the viewMode, tvMode, tvType, objID, catgID, objTypeID, or editMode parameter. (CVE-2020-13825)

  - CSV injection via
    the Title parameter that is mishandled in a CSV export. (CVE-2020-13826)" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  inject arbitrary HTML or JavaScript into the site or execute arbitrary code on the target machine." );
	script_tag( name: "affected", value: "i-doit CMDB through version 1.14.2." );
	script_tag( name: "solution", value: "Update to version 1.15 or later." );
	script_xref( name: "URL", value: "https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2020-005" );
	script_xref( name: "URL", value: "https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2020-006" );
	exit( 0 );
}
CPE = "cpe:/a:synetics:i-doit";
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
if(version_is_less( version: version, test_version: "1.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.15", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

