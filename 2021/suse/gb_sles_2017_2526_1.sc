if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2526.1" );
	script_cve_id( "CVE-2017-11671" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-12 01:29:00 +0000 (Thu, 12 Apr 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2526-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1|SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2526-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172526-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gcc48' package(s) announced via the SUSE-SU-2017:2526-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gcc48 fixes the following issues:
Security issues fixed:
- A new option -fstack-clash-protection is now offered, which mitigates
 the stack clash type of attacks. [bnc#1039513] Future maintenance
 releases of packages will be built with this option.
- CVE-2017-11671: Fixed rdrand/rdseed code generation issue [bsc#1050947]
Bugs fixed:
- Enable LFS support in 32bit libgcov.a. [bsc#1044016]
- Bump libffi version in libffi.pc to 3.0.11.
- Fix libffi issue for armv7l. [bsc#988274]
- Properly diagnose missing -fsanitize=address support on ppc64le.
 [bnc#1028744]
- Backport patch for PR65612. [bnc#1022062]
- Fixed DR#1288. [bnc#1011348]" );
	script_tag( name: "affected", value: "'gcc48' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP3, SUSE OpenStack Cloud 6." );
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
	if(!isnull( res = isrpmvuln( pkg: "cpp48", rpm: "cpp48~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpp48-debuginfo", rpm: "cpp48-debuginfo~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-32bit", rpm: "gcc48-32bit~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48", rpm: "gcc48~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-c++", rpm: "gcc48-c++~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-c++-debuginfo", rpm: "gcc48-c++-debuginfo~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-debuginfo", rpm: "gcc48-debuginfo~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-debugsource", rpm: "gcc48-debugsource~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-info", rpm: "gcc48-info~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-locale", rpm: "gcc48-locale~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0-32bit", rpm: "libasan0-32bit~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0-32bit-debuginfo", rpm: "libasan0-32bit-debuginfo~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0", rpm: "libasan0~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0-debuginfo", rpm: "libasan0-debuginfo~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++48-devel-32bit", rpm: "libstdc++48-devel-32bit~4.8.5~31.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++48-devel", rpm: "libstdc++48-devel~4.8.5~31.3.1", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "cpp48", rpm: "cpp48~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpp48-debuginfo", rpm: "cpp48-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-32bit", rpm: "gcc48-32bit~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48", rpm: "gcc48~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-c++", rpm: "gcc48-c++~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-c++-debuginfo", rpm: "gcc48-c++-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-debuginfo", rpm: "gcc48-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-debugsource", rpm: "gcc48-debugsource~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-info", rpm: "gcc48-info~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-locale", rpm: "gcc48-locale~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0-32bit", rpm: "libasan0-32bit~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0", rpm: "libasan0~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0-debuginfo", rpm: "libasan0-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++48-devel-32bit", rpm: "libstdc++48-devel-32bit~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++48-devel", rpm: "libstdc++48-devel~4.8.5~31.3.1", rls: "SLES12.0SP1" ) )){
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "cpp48", rpm: "cpp48~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpp48-debuginfo", rpm: "cpp48-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-32bit", rpm: "gcc48-32bit~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48", rpm: "gcc48~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-c++", rpm: "gcc48-c++~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-c++-debuginfo", rpm: "gcc48-c++-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-debuginfo", rpm: "gcc48-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-debugsource", rpm: "gcc48-debugsource~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-info", rpm: "gcc48-info~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-locale", rpm: "gcc48-locale~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0-32bit", rpm: "libasan0-32bit~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0", rpm: "libasan0~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0-debuginfo", rpm: "libasan0-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++48-devel-32bit", rpm: "libstdc++48-devel-32bit~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++48-devel", rpm: "libstdc++48-devel~4.8.5~31.3.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "cpp48", rpm: "cpp48~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpp48-debuginfo", rpm: "cpp48-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-32bit", rpm: "gcc48-32bit~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48", rpm: "gcc48~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-c++", rpm: "gcc48-c++~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-c++-debuginfo", rpm: "gcc48-c++-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-debuginfo", rpm: "gcc48-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-debugsource", rpm: "gcc48-debugsource~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-info", rpm: "gcc48-info~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc48-locale", rpm: "gcc48-locale~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0-32bit", rpm: "libasan0-32bit~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0", rpm: "libasan0~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan0-debuginfo", rpm: "libasan0-debuginfo~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++48-devel-32bit", rpm: "libstdc++48-devel-32bit~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++48-devel", rpm: "libstdc++48-devel~4.8.5~31.3.1", rls: "SLES12.0SP3" ) )){
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

