if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1184.1" );
	script_cve_id( "CVE-2017-5754", "CVE-2018-10471", "CVE-2018-10472", "CVE-2018-7540", "CVE-2018-7541", "CVE-2018-7542", "CVE-2018-8897" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1184-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1184-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181184-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2018:1184-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen to version 4.9.2 fixes several issues.
This feature was added:
- Added script, udev rule and systemd service to watch for vcpu
 online/offline events in a HVM domU. They are triggered via 'xl vcpu-set
 domU N'
These security issues were fixed:
- CVE-2018-8897: Prevent mishandling of debug exceptions on x86 (XSA-260,
 bsc#1090820)
- Handle HPET timers in IO-APIC mode correctly to prevent malicious or
 buggy HVM guests from causing a hypervisor crash or potentially
 privilege escalation/information leaks (XSA-261, bsc#1090822)
- Prevent unbounded loop, induced by qemu allowing an attacker to
 permanently keep a physical CPU core busy (XSA-262, bsc#1090823)
- CVE-2018-10472: x86 HVM guest OS users (in certain configurations) were
 able to read arbitrary dom0 files via QMP live insertion of a CDROM, in
 conjunction with specifying the target file as the backing file of a
 snapshot (bsc#1089152).
- CVE-2018-10471: x86 PV guest OS users were able to cause a denial of
 service (out-of-bounds zero write and hypervisor crash) via unexpected
 INT 80 processing, because of an incorrect fix for CVE-2017-5754
 (bsc#1089635).
- CVE-2018-7540: x86 PV guest OS users were able to cause a denial of
 service (host OS CPU hang) via non-preemptable L3/L4 pagetable freeing
 (bsc#1080635).
- CVE-2018-7541: Guest OS users were able to cause a denial of service
 (hypervisor crash) or gain privileges by triggering a grant-table
 transition from v2 to v1 (bsc#1080662).
- CVE-2018-7542: x86 PVH guest OS users were able to cause a denial of
 service (NULL pointer dereference and hypervisor crash) by leveraging
 the mishandling
 of configurations that lack a Local APIC (bsc#1080634).
These non-security issues were fixed:
- bsc#1087252: Update built-in defaults for xenstored in stubdom, keep
 default to run xenstored as daemon in dom0
- bsc#1087251: Preserve xen-syms from xen-dbg.gz to allow processing
 vmcores with crash(1)
- bsc#1072834: Prevent unchecked MSR access error" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.9.2_04~3.29.1", rls: "SLES12.0SP3" ) )){
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

