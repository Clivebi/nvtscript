if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851311" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-05-17 13:40:21 +0200 (Tue, 17 May 2016)" );
	script_cve_id( "CVE-2016-0264", "CVE-2016-0363", "CVE-2016-0376", "CVE-2016-0686", "CVE-2016-0687", "CVE-2016-3422", "CVE-2016-3426", "CVE-2016-3427", "CVE-2016-3443", "CVE-2016-3449", "CVE-2013-3009", "CVE-2013-5456" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for java-1_7_1-ibm (SUSE-SU-2016:1299-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_1-ibm'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This IBM Java 1.7.1 SR3 FP40 release fixes the following issues:

  Security issues fixed:

  - CVE-2016-0264: buffer overflow vulnerability in the IBM JVM (bsc#977648)

  - CVE-2016-0363: insecure use of invoke method in CORBA component,
  incorrect CVE-2013-3009 fix (bsc#977650)

  - CVE-2016-0376: insecure deserialization in CORBA, incorrect
  CVE-2013-5456 fix (bsc#977646)

  - The following CVEs got also fixed during this update. (bsc#979252)
  CVE-2016-3443, CVE-2016-0687, CVE-2016-0686, CVE-2016-3427,
  CVE-2016-3449, CVE-2016-3422, CVE-2016-3426" );
	script_tag( name: "affected", value: "java-1_7_1-ibm on SUSE Linux Enterprise Server 12" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2016:1299-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLES12\\.0SP0" );
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
if(release == "SLES12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr3.40~25.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr3.40~25.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr3.40~25.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr3.40~25.1", rls: "SLES12.0SP0" ) )){
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

