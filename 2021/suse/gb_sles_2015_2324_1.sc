if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.2324.1" );
	script_cve_id( "CVE-2015-3259", "CVE-2015-4106", "CVE-2015-5154", "CVE-2015-5239", "CVE-2015-5307", "CVE-2015-6815", "CVE-2015-7311", "CVE-2015-7504", "CVE-2015-7835", "CVE-2015-8104", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8341", "CVE-2015-8345" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:2324-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:2324-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20152324-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2015:2324-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes the following security issues:
- bsc#956832 - CVE-2015-8345: xen: qemu: net: eepro100: infinite loop in
 processing command block list
- Revert x86/IO-APIC: don't create pIRQ mapping from masked RTE until
 kernel maintenance release goes out.
- bsc#956592 - xen: virtual PMU is unsupported (XSA-163)
- bsc#956408 - CVE-2015-8339, CVE-2015-8340: xen: XENMEM_exchange error
 handling issues (XSA-159)
- bsc#956409 - CVE-2015-8341: xen: libxl leak of pv kernel and initrd on
 error (XSA-160)
- bsc#956411 - CVE-2015-7504: xen: heap buffer overflow vulnerability in
 pcnet emulator (XSA-162)
- bsc#947165 - CVE-2015-7311: xen: libxl fails to honour readonly flag on
 disks with qemu-xen (xsa-142)
- bsc#954405 - CVE-2015-8104: Xen: guest to host DoS by triggering an
 infinite loop in microcode via #DB exception
- bsc#954018 - CVE-2015-5307: xen: x86: CPU lockup during fault delivery
 (XSA-156)" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.5.2_02_k3.12.49_11~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default-debuginfo", rpm: "xen-kmp-default-debuginfo~4.5.2_02_k3.12.49_11~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.5.2_02~4.1", rls: "SLES12.0SP1" ) )){
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

