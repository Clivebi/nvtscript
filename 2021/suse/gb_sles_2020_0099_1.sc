if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0099.1" );
	script_cve_id( "CVE-2019-1547", "CVE-2019-1549", "CVE-2019-1551", "CVE-2019-1563" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0099-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0099-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200099-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl-1_1' package(s) announced via the SUSE-SU-2020:0099-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssl-1_1 fixes the following issues:

Security issue fixed:
CVE-2019-1551: Fixed an overflow bug in the x64_64 Montgomery squaring
 procedure used in exponentiation with 512-bit moduli (bsc#1158809).

CVE-2019-1563: Fixed bleichenbacher attack against cms/pkcs7 encryptioon
 transported key (bsc#1150250).

CVE-2019-1551: Fixed integer overflow in RSAZ modular exponentiation on
 x86_64 (bsc#1158809).

CVE-2019-1549: Fixed fork problem with random generator (bsc#1150247).

CVE-2019-1547: Fixed EC_GROUP_set_generator side channel attack
 avoidance (bsc#1150003).

Bug fixes:
Ship the openssl 1.1.1 binary as openssl-1_1, and make it installable in
 parallel with the system openssl (bsc#1140277).

Update to 1.1.1d (bsc#1133925, jsc#SLE-6430)." );
	script_tag( name: "affected", value: "'openssl-1_1' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1", rpm: "libopenssl1_1~1.1.1d~2.20.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-32bit", rpm: "libopenssl1_1-32bit~1.1.1d~2.20.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-debuginfo", rpm: "libopenssl1_1-debuginfo~1.1.1d~2.20.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-debuginfo-32bit", rpm: "libopenssl1_1-debuginfo-32bit~1.1.1d~2.20.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1", rpm: "openssl-1_1~1.1.1d~2.20.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-debuginfo", rpm: "openssl-1_1-debuginfo~1.1.1d~2.20.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-debugsource", rpm: "openssl-1_1-debugsource~1.1.1d~2.20.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1", rpm: "libopenssl1_1~1.1.1d~2.20.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-32bit", rpm: "libopenssl1_1-32bit~1.1.1d~2.20.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-debuginfo", rpm: "libopenssl1_1-debuginfo~1.1.1d~2.20.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-debuginfo-32bit", rpm: "libopenssl1_1-debuginfo-32bit~1.1.1d~2.20.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-debuginfo", rpm: "openssl-1_1-debuginfo~1.1.1d~2.20.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-debugsource", rpm: "openssl-1_1-debugsource~1.1.1d~2.20.1", rls: "SLES12.0SP5" ) )){
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

