if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.14160.1" );
	script_cve_id( "CVE-2019-11771", "CVE-2019-11775", "CVE-2019-2762", "CVE-2019-2766", "CVE-2019-2769", "CVE-2019-2816", "CVE-2019-4473", "CVE-2019-7317" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:19 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:45:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:14160-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:14160-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-201914160-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_1-ibm' package(s) announced via the SUSE-SU-2019:14160-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_7_1-ibm fixes the following issues:

Update to Java 7.1 Service Refresh 4 Fix Pack 50.

Security issues fixed:
CVE-2019-11771: IBM Security Update July 2019 (bsc#1147021)

CVE-2019-11775: IBM Security Update July 2019 (bsc#1147021)

CVE-2019-4473: IBM Security Update July 2019 (bsc#1147021)

CVE-2019-7317: Fixed issue inside Component AWT (libpng)(bsc#1141780).

CVE-2019-2769: Fixed issue inside Component Utilities (bsc#1141783).

CVE-2019-2762: Fixed issue inside Component Utilities (bsc#1141782).

CVE-2019-2816: Fixed issue inside Component Networking (bsc#1141785).

CVE-2019-2766: Fixed issue inside Component Networking (bsc#1141789)." );
	script_tag( name: "affected", value: "'java-1_7_1-ibm' package(s) on SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr4.50~26.44.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr4.50~26.44.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-devel", rpm: "java-1_7_1-ibm-devel~1.7.1_sr4.50~26.44.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr4.50~26.44.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr4.50~26.44.1", rls: "SLES11.0SP4" ) )){
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

