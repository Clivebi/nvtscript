if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1526.1" );
	script_cve_id( "CVE-2014-3065", "CVE-2014-3566", "CVE-2014-4288", "CVE-2014-6456", "CVE-2014-6457", "CVE-2014-6458", "CVE-2014-6466", "CVE-2014-6476", "CVE-2014-6492", "CVE-2014-6493", "CVE-2014-6502", "CVE-2014-6503", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6513", "CVE-2014-6515", "CVE-2014-6527", "CVE-2014-6531", "CVE-2014-6532", "CVE-2014-6558" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:15 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1526-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1526-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141526-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'IBM Java' package(s) announced via the SUSE-SU-2014:1526-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "java-1_7_0-ibm has been updated to version 1.7.0_sr7.2 to fix 21 security issues.

These security issues have been fixed:

 * Unspecified vulnerability (CVE-2014-3065).
 * The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
 products, uses nondeterministic CBC padding, which makes it easier
 for man-in-the-middle attackers to obtain cleartext data via a
 padding-oracle attack, aka the 'POODLE' issue (CVE-2014-3566).
 * Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20,
 and Java SE Embedded 7u60, allows remote attackers to affect
 confidentiality, integrity, and availability via vectors related to
 AWT (CVE-2014-6513).
 * Unspecified vulnerability in Oracle Java SE 7u67 and 8u20 allows
 remote attackers to affect confidentiality, integrity, and
 availability via unknown vectors (CVE-2014-6456).
 * Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20
 allows remote attackers to affect confidentiality, integrity, and
 availability via unknown vectors related to Deployment, a different
 vulnerability than CVE-2014-4288, CVE-2014-6493, and CVE-2014-6532
 (CVE-2014-6503).
 * Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20
 allows remote attackers to affect confidentiality, integrity, and
 availability via unknown vectors related to Deployment, a different
 vulnerability than CVE-2014-4288, CVE-2014-6493, and CVE-2014-6503
 (CVE-2014-6532).
 * Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20
 allows remote attackers to affect confidentiality, integrity, and
 availability via unknown vectors related to Deployment, a different
 vulnerability than CVE-2014-6493, CVE-2014-6503, and CVE-2014-6532
 (CVE-2014-4288).
 * Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20
 allows remote attackers to affect confidentiality, integrity, and
 availability via unknown vectors related to Deployment, a different
 vulnerability than CVE-2014-4288, CVE-2014-6503, and CVE-2014-6532
 (CVE-2014-6493).
 * Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20,
 when running on Firefox, allows remote attackers to affect
 confidentiality, integrity, and availability via unknown vectors
 related to Deployment (CVE-2014-6492).
 * Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20
 allows local users to affect confidentiality, integrity, and
 availability via unknown vectors related to Deployment
 (CVE-2014-6458).
 * Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20,
 when running on Internet Explorer, allows local users to affect
 confidentiality, integrity, and availability via unknown vectors
 related to Deployment (CVE-2014-6466).
 * Unspecified vulnerability in Oracle Java SE 5.0u71, 6u81, 7u67, and
 8u20, and Java SE Embedded 7u60, allows remote attackers to affect
 confidentiality, integrity, and availability via unknown vectors
 related to Libraries (CVE-2014-6506).
 * ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'IBM Java' package(s) on SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm", rpm: "java-1_6_0-ibm~1.6.0_sr16.2~0.3.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-alsa", rpm: "java-1_6_0-ibm-alsa~1.6.0_sr16.2~0.3.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-fonts", rpm: "java-1_6_0-ibm-fonts~1.6.0_sr16.2~0.3.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-jdbc", rpm: "java-1_6_0-ibm-jdbc~1.6.0_sr16.2~0.3.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_6_0-ibm-plugin", rpm: "java-1_6_0-ibm-plugin~1.6.0_sr16.2~0.3.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm", rpm: "java-1_7_0-ibm~1.7.0_sr8.0~0.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-alsa", rpm: "java-1_7_0-ibm-alsa~1.7.0_sr8.0~0.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-jdbc", rpm: "java-1_7_0-ibm-jdbc~1.7.0_sr8.0~0.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-ibm-plugin", rpm: "java-1_7_0-ibm-plugin~1.7.0_sr8.0~0.5.1", rls: "SLES11.0SP3" ) )){
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
