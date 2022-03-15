if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0471.1" );
	script_cve_id( "CVE-2013-0765", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783", "CVE-2013-0787" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-06 16:02:00 +0000 (Thu, 06 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0471-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0471-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130471-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2013:0471-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MozillaFirefox has been updated to the 17.0.4ESR release.
Besides the major version update from the 10ESR stable release line to the 17ESR stable release line, this update brings critical security and bugfixes:

 * MFSA 2013-29 / CVE-2013-0787: VUPEN Security, via TippingPoint's Zero Day Initiative, reported a use-after-free within the HTML editor when content script is run by the document.execCommand() function while internal editor operations are occurring. This could allow for arbitrary code execution.

The Firefox 17.0.3ESR release also contains lots of security fixes:

 * MFSA 2013-28: Security researcher Abhishek Arya
(Inferno) of the Google Chrome Security Team used the Address Sanitizer tool to discover a series of use-after-free, out of bounds read, and buffer overflow problems rated as low to critical security issues in shipped software. Some of these issues are potentially exploitable, allowing for remote code execution. We would also like to thank Abhishek for reporting four additional use-after-free and out of bounds write flaws introduced during Firefox development that were fixed before general release.

The following issues have been fixed in Firefox 19 and ESR 17.0.3:

 * Heap-use-after-free in nsOverflowContinuationTracker::Finish, with
 -moz-columns (CVE-2013-0780)
 *

 Heap-buffer-overflow WRITE in nsSaveAsCharset::DoCharsetConversion (CVE-2013-0782)

 *

 MFSA 2013-27 / CVE-2013-0776: Google security researcher Michal Zalewski reported an issue where the browser displayed the content of a proxy's 407 response if a user canceled the proxy's authentication prompt. In this circumstance, the addressbar will continue to show the requested site's address, including HTTPS addresses that appear to be secure. This spoofing of addresses can be used for phishing attacks by fooling users into entering credentials, for example.

 *

 MFSA 2013-26 / CVE-2013-0775: Security researcher Nils reported a use-after-free in nsImageLoadingContent when content script is executed. This could allow for arbitrary code execution.

 *

 MFSA 2013-25 / CVE-2013-0774: Mozilla security researcher Frederik Braun discovered that since Firefox 15 the file system location of the active browser profile was available to JavaScript workers. While not dangerous by itself, this could potentially be combined with other vulnerabilities to target the profile in an attack.

 *

 MFSA 2013-24 / CVE-2013-0773: Mozilla developer Bobby Holley discovered that it was possible to bypass some protections in Chrome Object Wrappers (COW) and System Only Wrappers (SOW), making their prototypes mutable by web content. This could be used leak information from chrome objects and possibly allow for arbitrary code execution.

 *

 MFSA 2013-23 / CVE-2013-0765: Mozilla developer Boris Zbarsky reported that in some circumstances a wrapped WebIDL object can be wrapped multiple times, overwriting the existing ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Mozilla Firefox' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~17.0.4esr~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-SLED", rpm: "MozillaFirefox-branding-SLED~7~0.10.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~17.0.4esr~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.9.4~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.9.4~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-64bit", rpm: "mozilla-nspr-64bit~4.9.4~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-devel", rpm: "mozilla-nspr-devel~4.9.4~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-x86", rpm: "mozilla-nspr-x86~4.9.4~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss", rpm: "mozilla-nss~3.14.1~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-32bit", rpm: "mozilla-nss-32bit~3.14.1~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-64bit", rpm: "mozilla-nss-64bit~3.14.1~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-devel", rpm: "mozilla-nss-devel~3.14.1~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools", rpm: "mozilla-nss-tools~3.14.1~0.6.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-x86", rpm: "mozilla-nss-x86~3.14.1~0.6.3", rls: "SLES10.0SP4" ) )){
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

