if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.14268.1" );
	script_cve_id( "CVE-2019-17015", "CVE-2019-17016", "CVE-2019-17017", "CVE-2019-17021", "CVE-2019-17022", "CVE-2019-17024", "CVE-2019-17026" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:11 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-13 20:15:00 +0000 (Mon, 13 Jan 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:14268-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:14268-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-202014268-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2020:14268-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaFirefox fixes the following issues:
Firefox Extended Support Release 68.4.1 ESR
 * Fixed: Security fix MFSA 2020-03 (bsc#1160498)
 * CVE-2019-17026 (bmo#1607443) IonMonkey type confusion with
 StoreElementHole and FallibleStoreElement Firefox Extended Support Release 68.4.0 ESR
 * Fixed: Various security fixes MFSA 2020-02 (bsc#1160305)
 * CVE-2019-17015 (bmo#1599005) Memory corruption in parent process
 during new content process initialization on Windows
 * CVE-2019-17016 (bmo#1599181) Bypass of @namespace CSS sanitization
 during pasting
 * CVE-2019-17017 (bmo#1603055) Type Confusion in XPCVariant.cpp
 * CVE-2019-17021 (bmo#1599008) Heap address disclosure in parent process
 during content process initialization on Windows
 * CVE-2019-17022 (bmo#1602843) CSS sanitization does not escape HTML tags
 * CVE-2019-17024 (bmo#1507180, bmo#1595470, bmo#1598605, bmo#1601826)
 Memory safety bugs fixed in Firefox 72 and Firefox ESR 68.4" );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~68.4.1~78.57.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~68.4.1~78.57.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~68.4.1~78.57.1", rls: "SLES11.0SP4" ) )){
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

