if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0593.2" );
	script_cve_id( "CVE-2015-0817", "CVE-2015-0818" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-22 02:59:00 +0000 (Thu, 22 Dec 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0593-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4|SLES11\\.0SP1|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0593-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150593-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2015:0593-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MozillaFirefox was updated to the 31.5.3ESR release to fix two security vulnerabilities:

 *

 MFSA 2015-29 / CVE-2015-0817: Security researcher ilxu1a reported,
through HP Zero Day Initiative's Pwn2Own contest, a flaw in Mozilla's implementation of typed array bounds checking in JavaScript just-in-time compilation (JIT) and its management of bounds checking for heap access.
This flaw can be leveraged into the reading and writing of memory allowing for arbitrary code execution on the local system.

 *

 MFSA 2015-28 / CVE-2015-0818: Security researcher Mariusz Mlynski reported, through HP Zero Day Initiative's Pwn2Own contest, a method to run arbitrary scripts in a privileged context. This bypassed the same-origin policy protections by using a flaw in the processing of SVG format content navigation.

Security Issues:

 * CVE-2015-0817
 * CVE-2015-0818" );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 11 SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~31.5.3esr~0.5.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~31.5.3esr~0.5.2", rls: "SLES10.0SP4" ) )){
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~31.5.3esr~0.3.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~31.5.3esr~0.3.1", rls: "SLES11.0SP1" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~31.5.3esr~0.3.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~31.5.3esr~0.3.1", rls: "SLES11.0SP2" ) )){
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
