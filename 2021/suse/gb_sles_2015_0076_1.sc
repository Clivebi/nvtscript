if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0076.1" );
	script_cve_id( "CVE-2014-1569", "CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8641" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-22 01:29:00 +0000 (Fri, 22 Sep 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0076-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0076-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150076-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2015:0076-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes the following security issues in MozillaFirefox:
- MFSA 2015-01/CVE-2014-8634/CVE-2014-8635 (bmo#1109889, bmo#1111737,
 bmo#1026774, bmo#1027300, bmo#1054538, bmo#1067473, bmo#1070962,
 bmo#1072130, bmo#1072871, bmo#1098583) Miscellaneous memory safety
 hazards (rv:35.0 / rv:31.4)
- MFSA 2015-03/CVE-2014-8638 (bmo#1080987) sendBeacon requests lack an
 Origin header
- MFSA 2015-04/CVE-2014-8639 (bmo#1095859) Cookie injection through Proxy
 Authenticate responses
- MFSA 2015-06/CVE-2014-8641 (bmo#1108455) Read-after-free in WebRTC

Also Mozilla NSS was updated to 3.17.3 to fix:
* The QuickDER decoder now decodes lengths robustly
 (bmo#1064670/CVE-2014-1569)
* Support for TLS_FALLBACK_SCSV has been added to the ssltap and tstclnt
 utilities
* Changes in CA certificates" );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~31.4.0esr~20.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~31.4.0esr~20.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~31.4.0esr~20.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~31.4.0esr~20.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3", rpm: "libfreebl3~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-32bit", rpm: "libfreebl3-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-debuginfo", rpm: "libfreebl3-debuginfo~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-debuginfo-32bit", rpm: "libfreebl3-debuginfo-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-hmac", rpm: "libfreebl3-hmac~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-hmac-32bit", rpm: "libfreebl3-hmac-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3", rpm: "libsoftokn3~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-32bit", rpm: "libsoftokn3-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-debuginfo", rpm: "libsoftokn3-debuginfo~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-debuginfo-32bit", rpm: "libsoftokn3-debuginfo-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-hmac", rpm: "libsoftokn3-hmac~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-hmac-32bit", rpm: "libsoftokn3-hmac-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss", rpm: "mozilla-nss~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-32bit", rpm: "mozilla-nss-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-certs", rpm: "mozilla-nss-certs~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-certs-32bit", rpm: "mozilla-nss-certs-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-certs-debuginfo", rpm: "mozilla-nss-certs-debuginfo~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-certs-debuginfo-32bit", rpm: "mozilla-nss-certs-debuginfo-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-debuginfo", rpm: "mozilla-nss-debuginfo~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-debuginfo-32bit", rpm: "mozilla-nss-debuginfo-32bit~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-debugsource", rpm: "mozilla-nss-debugsource~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools", rpm: "mozilla-nss-tools~3.17.3~16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools-debuginfo", rpm: "mozilla-nss-tools-debuginfo~3.17.3~16.1", rls: "SLES12.0" ) )){
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

