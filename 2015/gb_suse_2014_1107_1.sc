if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850796" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)" );
	script_cve_id( "CVE-2014-1562", "CVE-2014-1567" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for MozillaFirefox (SUSE-SU-2014:1107-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox was updated to the 24.8.0ESR release, fixing security
  issues and bugs.

  Only some of the published security advisories affect the Mozilla Firefox
  24ESR codestream:

  * MFSA 2014-72 / CVE-2014-1567: Security researcher regenrecht
  reported, via TippingPoint's Zero Day Initiative, a use-after-free
  during text layout when interacting with the setting of text
  direction. This results in a use-after-free which can lead to
  arbitrary code execution.

  * MFSA 2014-67: Mozilla developers and community identified and fixed
  several memory safety bugs in the browser engine used in Firefox and
  other Mozilla-based products. Some of these bugs showed evidence of
  memory corruption under certain circumstances, and we presume that with
  enough effort at least some of these could be exploited to run arbitrary
  code.

  * Jan de Mooij reported a memory safety problem that affects Firefox
  ESR 24.7, ESR 31 and Firefox 31. (CVE-2014-1562)" );
	script_xref( name: "URL", value: "https://www.mozilla.org/security/announce/" );
	script_tag( name: "affected", value: "MozillaFirefox on SUSE Linux Enterprise Server 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2014:1107-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLES11\\.0SP3" );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~24.8.0esr~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~24.8.0esr~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3", rpm: "libfreebl3~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3", rpm: "libsoftokn3~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.10.7~0.3.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss", rpm: "mozilla-nss~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools", rpm: "mozilla-nss-tools~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-32bit", rpm: "libfreebl3-32bit~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-32bit", rpm: "libsoftokn3-32bit~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.10.7~0.3.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-32bit", rpm: "mozilla-nss-32bit~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-x86", rpm: "libfreebl3-x86~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-x86", rpm: "libsoftokn3-x86~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-x86", rpm: "mozilla-nspr-x86~4.10.7~0.3.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-x86", rpm: "mozilla-nss-x86~3.16.4~0.8.1", rls: "SLES11.0SP3" ) )){
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

