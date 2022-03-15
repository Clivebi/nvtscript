if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0349.1" );
	script_cve_id( "CVE-2014-7840", "CVE-2014-8106" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-11 15:21:00 +0000 (Tue, 11 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0349-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0349-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150349-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2015:0349-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "QEMU was updated to fix various bugs and security issues.

Following security issues were fixed: CVE-2014-8106: Heap-based buffer overflow in the Cirrus VGA emulator (hw/display/cirrus_vga.c) in QEMU allowed local guest users to execute arbitrary code via vectors related to blit regions.

CVE-2014-7840: The host_from_stream_offset function in arch_init.c in QEMU, when loading RAM during migration, allowed remote attackers to execute arbitrary code via a crafted (1) offset or (2) length value in savevm data.

Also a bug was fixed where qemu-img convert could occasionaly corrupt images. (bsc#908380)" );
	script_tag( name: "affected", value: "'qemu' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "qemu", rpm: "qemu~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl", rpm: "qemu-block-curl~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl-debuginfo", rpm: "qemu-block-curl-debuginfo~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debugsource", rpm: "qemu-debugsource~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent-debuginfo", rpm: "qemu-guest-agent-debuginfo~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ipxe", rpm: "qemu-ipxe~1.0.0~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-lang", rpm: "qemu-lang~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc", rpm: "qemu-ppc~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc-debuginfo", rpm: "qemu-ppc-debuginfo~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390", rpm: "qemu-s390~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390-debuginfo", rpm: "qemu-s390-debuginfo~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-seabios", rpm: "qemu-seabios~1.7.4~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-sgabios", rpm: "qemu-sgabios~8~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools", rpm: "qemu-tools~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools-debuginfo", rpm: "qemu-tools-debuginfo~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vgabios", rpm: "qemu-vgabios~1.7.4~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86", rpm: "qemu-x86~2.0.2~42.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86-debuginfo", rpm: "qemu-x86-debuginfo~2.0.2~42.1", rls: "SLES12.0" ) )){
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

