if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2028.1" );
	script_cve_id( "CVE-2018-3639", "CVE-2019-2426", "CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2766", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2842", "CVE-2019-7317" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:51:00 +0000 (Wed, 14 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2028-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2028-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192028-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_0-openjdk' package(s) announced via the SUSE-SU-2019:2028-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_7_0-openjdk to version 7u231 fixes the following issues:

Security issues fixed:
CVE_2019-2426: Improve web server connections (bsc#1134297).

CVE-2019-2745: Improved ECC Implementation (bsc#1141784).

CVE-2019-2762: Exceptional throw cases (bsc#1141782).

CVE-2019-2766: Improve file protocol handling (bsc#1141789).

CVE-2019-2769: Better copies of CopiesList (bsc#1141783).

CVE-2019-2786: More limited privilege usage (bsc#1141787).

CVE-2019-2816: Normalize normalization (bsc#1141785).

CVE-2019-2842: Extended AES support (bsc#1141786).

CVE-2019-7317: Improve PNG support (bsc#1141780).

CVE-2018-3639: fix revision to prefer PR_SPEC_DISABLE_NOEXEC to
 PR_SPEC_DISABLE (bsc#1087082).

Certificate validation improvements" );
	script_tag( name: "affected", value: "'java-1_7_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk", rpm: "java-1_7_0-openjdk~1.7.0.231~43.27.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debuginfo", rpm: "java-1_7_0-openjdk-debuginfo~1.7.0.231~43.27.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debugsource", rpm: "java-1_7_0-openjdk-debugsource~1.7.0.231~43.27.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo", rpm: "java-1_7_0-openjdk-demo~1.7.0.231~43.27.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo-debuginfo", rpm: "java-1_7_0-openjdk-demo-debuginfo~1.7.0.231~43.27.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel", rpm: "java-1_7_0-openjdk-devel~1.7.0.231~43.27.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel-debuginfo", rpm: "java-1_7_0-openjdk-devel-debuginfo~1.7.0.231~43.27.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless", rpm: "java-1_7_0-openjdk-headless~1.7.0.231~43.27.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless-debuginfo", rpm: "java-1_7_0-openjdk-headless-debuginfo~1.7.0.231~43.27.2", rls: "SLES12.0SP4" ) )){
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

