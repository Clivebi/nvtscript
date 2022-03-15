if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1269.1" );
	script_cve_id( "CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2726", "CVE-2015-2728", "CVE-2015-2730", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2743", "CVE-2015-4000" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1269-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1269-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151269-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox, mozilla-nspr, mozilla-nss' package(s) announced via the SUSE-SU-2015:1269-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MozillaFirefox, mozilla-nspr and mozilla-nss were updated to fix 17 security issues.
For more details please check the changelogs.
- CVE-2015-2724/CVE-2015-2725/CVE-2015-2726: Miscellaneous memory safety
 hazards (bsc#935979).
- CVE-2015-2728: Type confusion in Indexed Database Manager (bsc#935979).
- CVE-2015-2730: ECDSA signature validation fails to handle some
 signatures correctly (bsc#935979).
- CVE-2015-2722/CVE-2015-2733: Use-after-free in workers while using
 XMLHttpRequest (bsc#935979).
-
CVE-2015-2734/CVE-2015-2735/CVE-2015-2736/CVE-2015-2737/CVE-2015-2738/CVE-2
 015-2739/CVE-2015-2740: Vulnerabilities found through code inspection
 (bsc#935979).
- CVE-2015-2743: Privilege escalation in PDF.js (bsc#935979).
- CVE-2015-4000: NSS accepts export-length DHE keys with regular DHE
 cipher suites (bsc#935033).
- CVE-2015-2721: NSS incorrectly permits skipping of ServerKeyExchange
 (bsc#935979)." );
	script_tag( name: "affected", value: "'MozillaFirefox, mozilla-nspr, mozilla-nss' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~31.8.0esr~37.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~31.8.0esr~37.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~31.8.0esr~37.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~31.8.0esr~37.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3", rpm: "libfreebl3~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-32bit", rpm: "libfreebl3-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-debuginfo", rpm: "libfreebl3-debuginfo~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-debuginfo-32bit", rpm: "libfreebl3-debuginfo-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-hmac", rpm: "libfreebl3-hmac~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-hmac-32bit", rpm: "libfreebl3-hmac-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3", rpm: "libsoftokn3~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-32bit", rpm: "libsoftokn3-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-debuginfo", rpm: "libsoftokn3-debuginfo~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-debuginfo-32bit", rpm: "libsoftokn3-debuginfo-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-hmac", rpm: "libsoftokn3-hmac~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-hmac-32bit", rpm: "libsoftokn3-hmac-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.10.8~3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.10.8~3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-debuginfo-32bit", rpm: "mozilla-nspr-debuginfo-32bit~4.10.8~3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-debuginfo", rpm: "mozilla-nspr-debuginfo~4.10.8~3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-debugsource", rpm: "mozilla-nspr-debugsource~4.10.8~3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss", rpm: "mozilla-nss~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-32bit", rpm: "mozilla-nss-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-certs", rpm: "mozilla-nss-certs~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-certs-32bit", rpm: "mozilla-nss-certs-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-certs-debuginfo", rpm: "mozilla-nss-certs-debuginfo~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-certs-debuginfo-32bit", rpm: "mozilla-nss-certs-debuginfo-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-debuginfo", rpm: "mozilla-nss-debuginfo~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-debuginfo-32bit", rpm: "mozilla-nss-debuginfo-32bit~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-debugsource", rpm: "mozilla-nss-debugsource~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools", rpm: "mozilla-nss-tools~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools-debuginfo", rpm: "mozilla-nss-tools-debuginfo~3.19.2_CKBI_1.98~21.1", rls: "SLES12.0" ) )){
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

