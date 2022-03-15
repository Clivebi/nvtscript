if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1175.1" );
	script_cve_id( "CVE-2016-1950", "CVE-2016-2834", "CVE-2016-8635", "CVE-2016-9574", "CVE-2017-5429", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5469" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-07 17:53:00 +0000 (Tue, 07 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1175-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1175-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171175-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox, mozilla-nss, mozilla-nspr' package(s) announced via the SUSE-SU-2017:1175-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox was updated to the Firefox ESR release 45.9.
Mozilla NSS was updated to support TLS 1.3 (close to release draft) and various new ciphers, PRFs, Diffie Hellman key agreement and support for more hashes.
Security issues fixed in Firefox (bsc#1035082)
- MFSA 2017-11/CVE-2017-5469: Potential Buffer overflow in flex-generated
 code
- MFSA 2017-11/CVE-2017-5429: Memory safety bugs fixed in Firefox 53,
 Firefox ESR 45.9, and Firefox ESR 52.1
- MFSA 2017-11/CVE-2017-5439: Use-after-free in nsTArray Length() during
 XSLT processing
- MFSA 2017-11/CVE-2017-5438: Use-after-free in nsAutoPtr during XSLT
 processing
- MFSA 2017-11/CVE-2017-5437: Vulnerabilities in Libevent library
- MFSA 2017-11/CVE-2017-5436: Out-of-bounds write with malicious font in
 Graphite 2
- MFSA 2017-11/CVE-2017-5435: Use-after-free during transaction processing
 in the editor
- MFSA 2017-11/CVE-2017-5434: Use-after-free during focus handling
- MFSA 2017-11/CVE-2017-5433: Use-after-free in SMIL animation functions
- MFSA 2017-11/CVE-2017-5432: Use-after-free in text input selection
- MFSA 2017-11/CVE-2017-5464: Memory corruption with accessibility and DOM
 manipulation
- MFSA 2017-11/CVE-2017-5465: Out-of-bounds read in ConvolvePixel
- MFSA 2017-11/CVE-2017-5460: Use-after-free in frame selection
- MFSA 2017-11/CVE-2017-5448: Out-of-bounds write in ClearKeyDecryptor
- MFSA 2017-11/CVE-2017-5446: Out-of-bounds read when HTTP/2 DATA frames
 are sent with incorrect data
- MFSA 2017-11/CVE-2017-5447: Out-of-bounds read during glyph processing
- MFSA 2017-11/CVE-2017-5444: Buffer overflow while parsing
 application/http-index-format content
- MFSA 2017-11/CVE-2017-5445: Uninitialized values used while parsing
 application/http-index-format content
- MFSA 2017-11/CVE-2017-5442: Use-after-free during style changes
- MFSA 2017-11/CVE-2017-5443: Out-of-bounds write during BinHex decoding
- MFSA 2017-11/CVE-2017-5440: Use-after-free in txExecutionState
 destructor during XSLT processing
- MFSA 2017-11/CVE-2017-5441: Use-after-free with selection during scroll
 events
- MFSA 2017-11/CVE-2017-5459: Buffer overflow in WebGL Mozilla NSS was updated to 3.29.5, bringing new features and fixing bugs:
- Update to NSS 3.29.5:
 * MFSA 2017-11/CVE-2017-5461: Rare crashes in the base 64 decoder and
 encoder were fixed.
 * MFSA 2017-11/CVE-2017-5462: A carry over bug in the RNG was fixed.
 * CVE-2016-9574: Remote DoS during session handshake when using
 SessionTicket extention and ECDHE-ECDSA (bsc#1015499).
 * requires NSPR >= 4.13.1
- Update to NSS 3.29.3
 * enables TLS 1.3 by default
- Fixed a bug in hash computation (and build with GCC 7 which complains
 about shifts of boolean values). (bsc#1030071, bmo#1348767)
- Update to NSS 3.28.3
 This is a patch release to fix binary compatibility issues.
- Update to NSS 3.28.1
 This is a patch release to update the list of root CA certificates.
 * The following CA ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'MozillaFirefox, mozilla-nss, mozilla-nspr' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Manager 2.1, SUSE Manager Proxy 2.1, SUSE OpenStack Cloud 5." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~45.9.0esr~71.2", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~45.9.0esr~71.2", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3", rpm: "libfreebl3~3.29.5~46.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-32bit", rpm: "libfreebl3-32bit~3.29.5~46.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3", rpm: "libsoftokn3~3.29.5~46.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-32bit", rpm: "libsoftokn3-32bit~3.29.5~46.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.13.1~32.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.13.1~32.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss", rpm: "mozilla-nss~3.29.5~46.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-32bit", rpm: "mozilla-nss-32bit~3.29.5~46.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools", rpm: "mozilla-nss-tools~3.29.5~46.1", rls: "SLES11.0SP3" ) )){
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~45.9.0esr~71.2", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~45.9.0esr~71.2", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3", rpm: "libfreebl3~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-32bit", rpm: "libfreebl3-32bit~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreebl3-x86", rpm: "libfreebl3-x86~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3", rpm: "libsoftokn3~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-32bit", rpm: "libsoftokn3-32bit~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoftokn3-x86", rpm: "libsoftokn3-x86~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.13.1~32.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.13.1~32.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-x86", rpm: "mozilla-nspr-x86~4.13.1~32.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss", rpm: "mozilla-nss~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-32bit", rpm: "mozilla-nss-32bit~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools", rpm: "mozilla-nss-tools~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-x86", rpm: "mozilla-nss-x86~3.29.5~46.1", rls: "SLES11.0SP4" ) )){
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

