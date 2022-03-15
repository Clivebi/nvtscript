if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2431.1" );
	script_cve_id( "CVE-2016-5250", "CVE-2016-5257", "CVE-2016-5261", "CVE-2016-5270", "CVE-2016-5272", "CVE-2016-5274", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5284" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-12 01:29:00 +0000 (Tue, 12 Jun 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2431-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2431-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162431-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2016:2431-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MozillaFirefox was updated to 45.4.0 ESR to fix the following issues
(bsc#999701):
The following security issue were fixed:
* MFSA 2016-86/CVE-2016-5270: Heap-buffer-overflow in
 nsCaseTransformTextRunFactory::TransformString
* MFSA 2016-86/CVE-2016-5272: Bad cast in nsImageGeometryMixin
* MFSA 2016-86/CVE-2016-5276: Heap-use-after-free in
 mozilla::a11y::DocAccessible::ProcessInvalidationList
* MFSA 2016-86/CVE-2016-5274: use-after-free in
 nsFrameManager::CaptureFrameState
* MFSA 2016-86/CVE-2016-5277: Heap-use-after-free in nsRefreshDriver::Tick
* MFSA 2016-86/CVE-2016-5278: Heap-buffer-overflow in
 nsBMPEncoder::AddImageFrame
* MFSA 2016-86/CVE-2016-5280: Use-after-free in
 mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap
* MFSA 2016-86/CVE-2016-5281: use-after-free in DOMSVGLength
* MFSA 2016-86/CVE-2016-5284: Add-on update site certificate pin expiration
* MFSA 2016-86/CVE-2016-5250: Resource Timing API is storing resources
 sent by the previous page
* MFSA 2016-86/CVE-2016-5261: Integer overflow and memory corruption in
 WebSocketChannel
* MFSA 2016-86/CVE-2016-5257: Various memory safety bugs fixed in Firefox
 49 and Firefox ESR 45.4" );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on SUSE Linux Enterprise Debuginfo 11-SP2, SUSE Linux Enterprise Server 11-SP2." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~45.4.0esr~52.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~45.4.0esr~52.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

