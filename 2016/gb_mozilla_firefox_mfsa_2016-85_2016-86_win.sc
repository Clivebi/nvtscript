CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809324" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2016-2827", "CVE-2016-5270", "CVE-2016-5271", "CVE-2016-5272", "CVE-2016-5273", "CVE-2016-5276", "CVE-2016-5274", "CVE-2016-5277", "CVE-2016-5275", "CVE-2016-5278", "CVE-2016-5279", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5282", "CVE-2016-5283", "CVE-2016-5284", "CVE-2016-5256", "CVE-2016-5257" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-23 10:23:36 +0530 (Fri, 23 Sep 2016)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2016-85_2016-86) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Out-of-bounds read in mozilla::net::IsValidReferrerPolicy.

  - Heap-buffer-overflow in nsCaseTransformTextRunFactory::TransformString.

  - Out-of-bounds read in PropertyProvider::GetSpacingInternal.

  - Bad cast in nsImageGeometryMixin.

  - Crash in mozilla::a11y::HyperTextAccessible::GetChildOffset.

  - Heap-use-after-free in mozilla::a11y::DocAccessible::ProcessInvalidationList.

  - Use-after-free in nsFrameManager::CaptureFrameState.

  - Heap-use-after-free in nsRefreshDriver::Tick.

  - Global-buffer-overflow in mozilla::gfx::FilterSupport::ComputeSourceNeededRegions.

  - Heap-buffer-overflow in nsBMPEncoder::AddImageFrame.

  - Full local path of files is available to web pages after drag and drop.

  - Use-after-free in mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap.

  - Use-after-free in DOMSVGLength.

  - Favicons can be loaded through non-whitelisted protocols.

  - 'iframe src' fragment timing attack can reveal cross-origin data.

  - Add-on update site certificate pin expiration.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities remote attackers to cause a denial of service, to execute
  arbitrary code, to obtain sensitive full-pathname information." );
	script_tag( name: "affected", value: "Mozilla Firefox versions before 49." );
	script_tag( name: "solution", value: "Update to version 49 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-85/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "49" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "49", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

