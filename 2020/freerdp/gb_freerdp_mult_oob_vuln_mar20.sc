if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112745" );
	script_version( "2021-08-16T09:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 09:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-13 08:54:57 +0000 (Wed, 13 May 2020)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-30 02:15:00 +0000 (Sun, 30 Aug 2020)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-11045", "CVE-2020-11046", "CVE-2020-11048" );
	script_name( "FreeRDP > 1.0.0 & < 2.0.0 Multiple Out-of-Bounds Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_freerdp_detect_lin.sc" );
	script_mandatory_keys( "FreeRDP/Linux/Ver" );
	script_tag( name: "summary", value: "FreeRDP is prone to multiple out-of-bounds vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - An out-of-bound read in update_read_bitmap_data allows client memory to be read to an image buffer (CVE-2020-11045)

  - A stream out-of-bounds seek in update_read_synchronize could lead to a later out-of-bounds read (CVE-2020-11046)

  - An out-of-bounds read allows to abort a session. No data extraction is possible (CVE-2020-11048)" );
	script_tag( name: "affected", value: "FreeRDP after 1.0.0 and before 2.0.0." );
	script_tag( name: "solution", value: "Update FreeRDP to version 2.0.0 or later." );
	script_xref( name: "URL", value: "https://github.com/FreeRDP/FreeRDP/issues/6005" );
	script_xref( name: "URL", value: "https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-3x39-248q-f4q6" );
	script_xref( name: "URL", value: "https://github.com/FreeRDP/FreeRDP/issues/6006" );
	script_xref( name: "URL", value: "https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-hx48-wmmm-mr5q" );
	script_xref( name: "URL", value: "https://github.com/FreeRDP/FreeRDP/issues/6007" );
	script_xref( name: "URL", value: "https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-hv8w-f2hx-5gcv" );
	exit( 0 );
}
CPE = "cpe:/a:freerdp_project:freerdp";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_greater( version: version, test_version: "1.0.0" ) && version_is_less( version: version, test_version: "2.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

