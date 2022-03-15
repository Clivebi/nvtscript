if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.1426.1" );
	script_cve_id( "CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-12 17:45:00 +0000 (Wed, 12 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:1426-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:1426-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20121426-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2012:1426-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MozillaFirefox was updated to the 10.0.10ESR security release.

The following issues have been fixed:

 *

 MFSA 2012-90: Mozilla has fixed a number of issues related to the Location object in order to enhance overall security. Details for each of the current fixed issues are below.

 Thunderbird is only affected by window.location issues through RSS feeds and extensions that load web content.

 *

 CVE-2012-4194: Security researcher Mariusz Mlynski reported that the true value of window.location could be shadowed by user content through the use of the valueOf method, which can be combined with some plugins to perform a cross-site scripting (XSS) attack on users.

 *

 CVE-2012-4195: Mozilla security researcher moz_bug_r_a4 discovered that the CheckURL function in window.location can be forced to return the wrong calling document and principal, allowing a cross-site scripting
(XSS) attack. There is also the possibility of gaining arbitrary code execution if the attacker can take advantage of an add-on that interacts with the page content.

 *

 CVE-2012-4196: Security researcher Antoine Delignat-Lavaud of the PROSECCO research team at INRIA Paris reported the ability to use property injection by prototype to bypass security wrapper protections on the Location object, allowing the cross-origin reading of the Location object." );
	script_tag( name: "affected", value: "'Mozilla Firefox' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~10.0.10~0.5.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~10.0.10~0.5.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.9.3~0.5.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.9.3~0.5.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-64bit", rpm: "mozilla-nspr-64bit~4.9.3~0.5.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-devel", rpm: "mozilla-nspr-devel~4.9.3~0.5.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-x86", rpm: "mozilla-nspr-x86~4.9.3~0.5.1", rls: "SLES10.0SP4" ) )){
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~10.0.10~0.3.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~10.0.10~0.3.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.9.3~0.2.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.9.3~0.2.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-x86", rpm: "mozilla-nspr-x86~4.9.3~0.2.1", rls: "SLES11.0SP2" ) )){
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

