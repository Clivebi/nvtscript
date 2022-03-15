if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883179" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2019-14816", "CVE-2019-14895", "CVE-2019-14898", "CVE-2019-14901", "CVE-2019-17133", "CVE-2019-11599" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-12 16:15:00 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2020-02-06 04:00:51 +0000 (Thu, 06 Feb 2020)" );
	script_name( "CentOS: Security Advisory for bpftool (CESA-2020:0375)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:0375" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-February/035620.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2020:0375 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The kernel-rt packages provide the Real Time Linux Kernel, which enables
fine-tuning for systems with extremely high determinism requirements.

Security Fix(es):

  * kernel: heap overflow in mwifiex_update_vs_ie() function of Marvell WiFi
driver (CVE-2019-14816)

  * kernel: heap-based buffer overflow in mwifiex_process_country_ie()
function in drivers/net/wireless/marvell/mwifiex/sta_ioctl.c
(CVE-2019-14895)

  * kernel: heap overflow in marvell/mwifiex/tdls.c (CVE-2019-14901)

  * kernel: buffer overflow in cfg80211_mgd_wext_giwessid in
net/wireless/wext-sme.c (CVE-2019-17133)

  * kernel: incomplete fix  for race condition between
mmget_not_zero()/get_task_mm() and core dumping in CVE-2019-11599
(CVE-2019-14898)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * patchset for x86/atomic: Fix smp_mb__{before, after}_atomic() [kernel-rt]
(BZ#1772522)

  * kernel-rt: update to the RHEL7.7.z batch#4 source tree (BZ#1780322)

  * kvm nx_huge_pages_recovery_ratio=0 is needed to meet KVM-RT low latency
requirement (BZ#1781157)

  * kernel-rt:  hard lockup panic in during execution of CFS bandwidth period
timer (BZ#1788057)" );
	script_tag( name: "affected", value: "'bpftool' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "bpftool", rpm: "bpftool~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-abi-whitelists", rpm: "kernel-abi-whitelists~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs-devel", rpm: "kernel-tools-libs-devel~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perf", rpm: "perf~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~3.10.0~1062.12.1.el7", rls: "CentOS7" ) )){
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

