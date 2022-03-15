if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0394.1" );
	script_cve_id( "CVE-2019-14250", "CVE-2019-15847" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 13:38:00 +0000 (Thu, 17 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0394-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1|SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0394-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200394-1/" );
	script_xref( name: "URL", value: "https://gcc.gnu.org/gcc-9/changes.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gcc9' package(s) announced via the SUSE-SU-2020:0394-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gcc9 fixes the following issues:

The GNU Compiler Collection is shipped in version 9.

A detailed changelog on what changed in GCC 9 is available at [link moved to references]

The compilers have been added to the SUSE Linux Enterprise Toolchain Module.

To use these compilers, install e.g. gcc9, gcc9-c++ and build with CC=gcc-9 CXX=g++-9 set.

For SUSE Linux Enterprise base products, the libstdc++6, libgcc_s1 and other compiler libraries have been switched from their gcc8 variants to
 their gcc9 variants.

Security issues fixed:
CVE-2019-15847: Fixed a miscompilation in the POWER9 back end, that
 optimized multiple calls of the __builtin_darn intrinsic into a single
 call. (bsc#1149145)

CVE-2019-14250: Fixed a heap overflow in the LTO linker. (bsc#1142649)

Non-security issues fixed:
Split out libstdc++ pretty-printers into a separate package
 supplementing gdb and the installed runtime. (bsc#1135254)

Fixed miscompilation for vector shift on s390. (bsc#1141897)" );
	script_tag( name: "affected", value: "'gcc9' package(s) on HPE Helion Openstack 8, SUSE Enterprise Storage 5, SUSE Linux Enterprise Module for Toolchain 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debuginfo", rpm: "gcc9-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debugsource", rpm: "gcc9-debugsource~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-32bit", rpm: "libasan5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-32bit-debuginfo", rpm: "libasan5-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5", rpm: "libasan5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-debuginfo", rpm: "libasan5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-32bit", rpm: "libatomic1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-32bit-debuginfo", rpm: "libatomic1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1", rpm: "libatomic1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-debuginfo", rpm: "libatomic1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-32bit", rpm: "libgcc_s1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-32bit-debuginfo", rpm: "libgcc_s1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1", rpm: "libgcc_s1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-debuginfo", rpm: "libgcc_s1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-32bit", rpm: "libgfortran5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-32bit-debuginfo", rpm: "libgfortran5-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5", rpm: "libgfortran5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-debuginfo", rpm: "libgfortran5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-32bit", rpm: "libgo14-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-32bit-debuginfo", rpm: "libgo14-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14", rpm: "libgo14~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-debuginfo", rpm: "libgo14-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-32bit", rpm: "libgomp1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-32bit-debuginfo", rpm: "libgomp1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1", rpm: "libgomp1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-debuginfo", rpm: "libgomp1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-32bit", rpm: "libitm1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-32bit-debuginfo", rpm: "libitm1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1", rpm: "libitm1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-debuginfo", rpm: "libitm1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0", rpm: "liblsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0-debuginfo", rpm: "liblsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-32bit", rpm: "libquadmath0-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-32bit-debuginfo", rpm: "libquadmath0-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0", rpm: "libquadmath0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-debuginfo", rpm: "libquadmath0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-32bit", rpm: "libstdc++6-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-32bit-debuginfo", rpm: "libstdc++6-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6", rpm: "libstdc++6~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-debuginfo", rpm: "libstdc++6-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-locale", rpm: "libstdc++6-locale~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0", rpm: "libtsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0-debuginfo", rpm: "libtsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-32bit", rpm: "libubsan1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-32bit-debuginfo", rpm: "libubsan1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1", rpm: "libubsan1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-debuginfo", rpm: "libubsan1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP1" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debuginfo", rpm: "gcc9-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debugsource", rpm: "gcc9-debugsource~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-32bit", rpm: "libasan5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-32bit-debuginfo", rpm: "libasan5-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5", rpm: "libasan5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-debuginfo", rpm: "libasan5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-32bit", rpm: "libatomic1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1", rpm: "libatomic1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-debuginfo", rpm: "libatomic1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-32bit", rpm: "libgcc_s1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1", rpm: "libgcc_s1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-debuginfo", rpm: "libgcc_s1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-32bit", rpm: "libgfortran5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5", rpm: "libgfortran5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-debuginfo", rpm: "libgfortran5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-32bit", rpm: "libgo14-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14", rpm: "libgo14~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-debuginfo", rpm: "libgo14-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-32bit", rpm: "libgomp1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1", rpm: "libgomp1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-debuginfo", rpm: "libgomp1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-32bit", rpm: "libitm1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1", rpm: "libitm1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-debuginfo", rpm: "libitm1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0", rpm: "liblsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0-debuginfo", rpm: "liblsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-32bit", rpm: "libquadmath0-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0", rpm: "libquadmath0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-debuginfo", rpm: "libquadmath0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-32bit", rpm: "libstdc++6-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6", rpm: "libstdc++6~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-debuginfo", rpm: "libstdc++6-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-locale", rpm: "libstdc++6-locale~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0", rpm: "libtsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0-debuginfo", rpm: "libtsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-32bit", rpm: "libubsan1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-32bit-debuginfo", rpm: "libubsan1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1", rpm: "libubsan1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-debuginfo", rpm: "libubsan1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debuginfo", rpm: "gcc9-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debugsource", rpm: "gcc9-debugsource~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-32bit", rpm: "libasan5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-32bit-debuginfo", rpm: "libasan5-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5", rpm: "libasan5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-debuginfo", rpm: "libasan5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-32bit", rpm: "libatomic1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-32bit-debuginfo", rpm: "libatomic1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1", rpm: "libatomic1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-debuginfo", rpm: "libatomic1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-32bit", rpm: "libgcc_s1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-32bit-debuginfo", rpm: "libgcc_s1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1", rpm: "libgcc_s1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-debuginfo", rpm: "libgcc_s1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-32bit", rpm: "libgfortran5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-32bit-debuginfo", rpm: "libgfortran5-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5", rpm: "libgfortran5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-debuginfo", rpm: "libgfortran5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-32bit", rpm: "libgo14-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-32bit-debuginfo", rpm: "libgo14-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14", rpm: "libgo14~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-debuginfo", rpm: "libgo14-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-32bit", rpm: "libgomp1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-32bit-debuginfo", rpm: "libgomp1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1", rpm: "libgomp1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-debuginfo", rpm: "libgomp1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-32bit", rpm: "libitm1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-32bit-debuginfo", rpm: "libitm1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1", rpm: "libitm1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-debuginfo", rpm: "libitm1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0", rpm: "liblsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0-debuginfo", rpm: "liblsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-32bit", rpm: "libquadmath0-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-32bit-debuginfo", rpm: "libquadmath0-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0", rpm: "libquadmath0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-debuginfo", rpm: "libquadmath0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-32bit", rpm: "libstdc++6-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-32bit-debuginfo", rpm: "libstdc++6-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6", rpm: "libstdc++6~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-debuginfo", rpm: "libstdc++6-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-locale", rpm: "libstdc++6-locale~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0", rpm: "libtsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0-debuginfo", rpm: "libtsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-32bit", rpm: "libubsan1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-32bit-debuginfo", rpm: "libubsan1-32bit-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1", rpm: "libubsan1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-debuginfo", rpm: "libubsan1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debuginfo", rpm: "gcc9-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debugsource", rpm: "gcc9-debugsource~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-32bit", rpm: "libasan5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5", rpm: "libasan5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-debuginfo", rpm: "libasan5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-32bit", rpm: "libatomic1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1", rpm: "libatomic1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-debuginfo", rpm: "libatomic1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-32bit", rpm: "libgcc_s1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1", rpm: "libgcc_s1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-debuginfo", rpm: "libgcc_s1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-32bit", rpm: "libgfortran5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5", rpm: "libgfortran5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-debuginfo", rpm: "libgfortran5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-32bit", rpm: "libgo14-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14", rpm: "libgo14~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-debuginfo", rpm: "libgo14-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-32bit", rpm: "libgomp1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1", rpm: "libgomp1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-debuginfo", rpm: "libgomp1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-32bit", rpm: "libitm1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1", rpm: "libitm1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-debuginfo", rpm: "libitm1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0", rpm: "liblsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0-debuginfo", rpm: "liblsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-32bit", rpm: "libquadmath0-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0", rpm: "libquadmath0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-debuginfo", rpm: "libquadmath0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-32bit", rpm: "libstdc++6-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6", rpm: "libstdc++6~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-debuginfo", rpm: "libstdc++6-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-locale", rpm: "libstdc++6-locale~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0", rpm: "libtsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0-debuginfo", rpm: "libtsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-32bit", rpm: "libubsan1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1", rpm: "libubsan1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-debuginfo", rpm: "libubsan1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debuginfo", rpm: "gcc9-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc9-debugsource", rpm: "gcc9-debugsource~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-32bit", rpm: "libasan5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5", rpm: "libasan5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasan5-debuginfo", rpm: "libasan5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-32bit", rpm: "libatomic1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1", rpm: "libatomic1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libatomic1-debuginfo", rpm: "libatomic1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-32bit", rpm: "libgcc_s1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1", rpm: "libgcc_s1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc_s1-debuginfo", rpm: "libgcc_s1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-32bit", rpm: "libgfortran5-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5", rpm: "libgfortran5~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran5-debuginfo", rpm: "libgfortran5-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-32bit", rpm: "libgo14-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14", rpm: "libgo14~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgo14-debuginfo", rpm: "libgo14-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-32bit", rpm: "libgomp1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1", rpm: "libgomp1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp1-debuginfo", rpm: "libgomp1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-32bit", rpm: "libitm1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1", rpm: "libitm1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libitm1-debuginfo", rpm: "libitm1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0", rpm: "liblsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblsan0-debuginfo", rpm: "liblsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-32bit", rpm: "libquadmath0-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0", rpm: "libquadmath0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath0-debuginfo", rpm: "libquadmath0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-32bit", rpm: "libstdc++6-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6", rpm: "libstdc++6~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-debuginfo", rpm: "libstdc++6-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++6-locale", rpm: "libstdc++6-locale~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0", rpm: "libtsan0~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtsan0-debuginfo", rpm: "libtsan0-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-32bit", rpm: "libubsan1-32bit~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1", rpm: "libubsan1~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libubsan1-debuginfo", rpm: "libubsan1-debuginfo~9.2.1+r275327~1.3.9", rls: "SLES12.0SP5" ) )){
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

