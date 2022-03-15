if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0905.1" );
	script_cve_id( "CVE-2014-1533", "CVE-2014-1534", "CVE-2014-1536", "CVE-2014-1537", "CVE-2014-1538", "CVE-2014-1541", "CVE-2014-1545" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-28 02:29:00 +0000 (Thu, 28 Dec 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0905-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP3|SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0905-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140905-1/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/security/announce/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2014:0905-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox has been updated to 24.6.0 to fix the following security issues:

 * Miscellaneous memory safety hazards (CVE-2014-1533/CVE-2014-1534)
 * Use-after-free and out of bounds issues found using Address
 Sanitizer (CVE-2014-1536/CVE-2014-1537/CVE-2014-1538)
 * Use-after-free with SMIL Animation Controller (CVE-2014-1541)

mozilla-nspr has been updated to version 4.10.6 to fix one security issue:

 * Out of bounds write in NSPR (CVE-2014-1545)

Further information can be found at [link moved to references]

Security Issues:

 * CVE-2014-1533
 * CVE-2014-1534
 * CVE-2014-1536
 * CVE-2014-1537
 * CVE-2014-1538
 * CVE-2014-1541
 * CVE-2014-1545" );
	script_tag( name: "affected", value: "'Mozilla Firefox' package(s) on SUSE Linux Enterprise Server 10 SP3, SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~24.6.0esr~0.5.4", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-SLED", rpm: "MozillaFirefox-branding-SLED~24~0.12.4", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~24.6.0esr~0.5.4", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.10.6~0.5.4", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.10.6~0.5.4", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-devel", rpm: "mozilla-nspr-devel~4.10.6~0.5.4", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss", rpm: "mozilla-nss~3.16.1~0.5.4", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-32bit", rpm: "mozilla-nss-32bit~3.16.1~0.5.4", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-devel", rpm: "mozilla-nss-devel~3.16.1~0.5.4", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools", rpm: "mozilla-nss-tools~3.16.1~0.5.4", rls: "SLES10.0SP3" ) )){
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~24.6.0esr~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-SLED", rpm: "MozillaFirefox-branding-SLED~24~0.12.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~24.6.0esr~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.10.6~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.10.6~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-devel", rpm: "mozilla-nspr-devel~4.10.6~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss", rpm: "mozilla-nss~3.16.1~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-32bit", rpm: "mozilla-nss-32bit~3.16.1~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-devel", rpm: "mozilla-nss-devel~3.16.1~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nss-tools", rpm: "mozilla-nss-tools~3.16.1~0.5.4", rls: "SLES10.0SP4" ) )){
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

