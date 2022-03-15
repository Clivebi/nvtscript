if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3045.1" );
	script_cve_id( "CVE-2018-2938", "CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2973" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:36 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3045-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3045-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183045-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2018:3045-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_8_0-openjdk to the jdk8u181 (icedtea 3.9.0) release fixes the following issues:

These security issues were fixed:
CVE-2018-2938: Difficult to exploit vulnerability allowed
 unauthenticated attacker with network access via multiple protocols to
 compromise Java SE. Successful attacks of this vulnerability can result
 in takeover of Java SE (bsc#1101644).

CVE-2018-2940: Vulnerability in subcomponent: Libraries. Easily
 exploitable vulnerability allowed unauthenticated attacker with network
 access via multiple protocols to compromise Java SE, Java SE Embedded.
 Successful attacks require human interaction from a person other than
 the attacker. Successful attacks of this vulnerability can result in
 unauthorized read access to a subset of Java SE, Java SE Embedded
 accessible data (bsc#1101645)

CVE-2018-2952: Vulnerability in subcomponent: Concurrency. Difficult to
 exploit vulnerability allowed unauthenticated attacker with network
 access via multiple protocols to compromise Java SE, Java SE Embedded,
 JRockit. Successful attacks of this vulnerability can result in
 unauthorized ability to cause a partial denial of service (partial DOS)
 of Java SE, Java SE Embedded, JRockit (bsc#1101651)

CVE-2018-2973: Vulnerability in subcomponent: JSSE. Difficult to exploit
 vulnerability allowed unauthenticated attacker with network access via
 SSL/TLS to compromise Java SE, Java SE Embedded. Successful attacks of
 this vulnerability can result in unauthorized creation, deletion or
 modification access to critical data or all Java SE, Java SE Embedded
 accessible data (bsc#1101656)

These non-security issues were fixed:
Improve desktop file usage

Better Internet address support

speculative traps break when classes are redefined

sun/security/pkcs11/ec/ReadCertificates.java fails intermittently

Clean up code that saves the previous versions of redefined classes

Prevent SIGSEGV in ReceiverTypeData::clean_weak_klass_links

RedefineClasses() tests fail assert(((Metadata*)obj)->is_valid())
 failed: obj is valid

NMT is not enabled if NMT option is specified after class path specifiers

EndEntityChecker should not process custom extensions after PKIX
 validation

SupportedDSAParamGen.java failed with timeout

Montgomery multiply intrinsic should use correct name

When determining the ciphersuite lists, there is no debug output for
 disabled suites.

sun/security/mscapi/SignedObjectChain.java fails on Windows

On Windows Swing changes keyboard layout on a window activation

IfNode::range_check_trap_proj() should handler dying subgraph with
 single if proj

Even better Internet address support

Newlines in JAXB string values of SOAP-requests are escaped to '
'

TestFlushableGZIPOutputStream failing with IndexOutOfBoundsException

Unable to use JDWP API in JDK 8 to debug JDK 9 VM

Hotspot crash on Cassandra 3.11.1 startup with libnuma 2.0.3

Performance drop ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'java-1_8_0-openjdk' package(s) on SUSE Linux Enterprise Module for Legacy Software 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk", rpm: "java-1_8_0-openjdk~1.8.0.181~3.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debuginfo", rpm: "java-1_8_0-openjdk-debuginfo~1.8.0.181~3.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debugsource", rpm: "java-1_8_0-openjdk-debugsource~1.8.0.181~3.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo", rpm: "java-1_8_0-openjdk-demo~1.8.0.181~3.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo-debuginfo", rpm: "java-1_8_0-openjdk-demo-debuginfo~1.8.0.181~3.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel", rpm: "java-1_8_0-openjdk-devel~1.8.0.181~3.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel-debuginfo", rpm: "java-1_8_0-openjdk-devel-debuginfo~1.8.0.181~3.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless", rpm: "java-1_8_0-openjdk-headless~1.8.0.181~3.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless-debuginfo", rpm: "java-1_8_0-openjdk-headless-debuginfo~1.8.0.181~3.10.1", rls: "SLES15.0" ) )){
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
