if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1331.1" );
	script_cve_id( "CVE-2015-1931", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1331-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1331-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151331-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_1-ibm' package(s) announced via the SUSE-SU-2015:1331-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "IBM Java was updated to 7.1-3.10 to fix several security issues.
The following vulnerabilities were fixed:
* CVE-2015-1931: IBM Java Security Components store plain text data in
 memory dumps, which could allow a local attacker to obtain information
 to aid in further attacks against the system.
* CVE-2015-2590: Easily exploitable vulnerability in the Libraries
 component allowed successful unauthenticated network attacks via
 multiple protocols. Successful attack of this vulnerability could have
 resulted in unauthorized Operating System takeover including arbitrary
 code execution.
* CVE-2015-2601: Easily exploitable vulnerability in the JCE component
 allowed successful unauthenticated network attacks via multiple
 protocols. Successful attack of this vulnerability could have resulted
 in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2613: Easily exploitable vulnerability in the JCE component
 allowed successful unauthenticated network attacks via multiple
 protocols. Successful attack of this vulnerability could have resulted
 in unauthorized read access to a subset of Java SE, Java SE Embedded
 accessible data.
* CVE-2015-2619: Easily exploitable vulnerability in the 2D component
 allowed successful unauthenticated network attacks via multiple
 protocols. Successful attack of this vulnerability could have resulted
 in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2621: Easily exploitable vulnerability in the JMX component
 allowed successful unauthenticated network attacks via multiple
 protocols. Successful attack of this vulnerability could have resulted
 in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2625: Very difficult to exploit vulnerability in the JSSE
 component allowed successful unauthenticated network attacks via
 SSL/TLS. Successful attack of this vulnerability could have resulted in
 unauthorized read access to a subset of Java accessible data.
* CVE-2015-2632: Easily exploitable vulnerability in the 2D component
 allowed successful unauthenticated network attacks via multiple
 protocols. Successful attack of this vulnerability could have resulted
 in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2637: Easily exploitable vulnerability in the 2D component
 allowed successful unauthenticated network attacks via multiple
 protocols. Successful attack of this vulnerability could have resulted
 in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2638: Easily exploitable vulnerability in the 2D component
 allowed successful unauthenticated network attacks via multiple
 protocols. Successful attack of this vulnerability could have resulted
 in unauthorized Operating System takeover including arbitrary code
 execution.
* CVE-2015-2664: Difficult to exploit vulnerability in the Deployment
 component requiring logon to Operating ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'java-1_7_1-ibm' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr3.10~14.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr3.10~14.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr3.10~14.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr3.10~14.1", rls: "SLES12.0" ) )){
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

