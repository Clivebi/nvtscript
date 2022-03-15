if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883066" );
	script_version( "2021-08-27T14:01:18+0000" );
	script_cve_id( "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-27 14:01:18 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-06-19 02:00:47 +0000 (Wed, 19 Jun 2019)" );
	script_name( "CentOS Update for kernel CESA-2019:1481 centos7 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:1481" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-June/023333.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the CESA-2019:1481 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * An integer overflow flaw was found in the way the Linux kernel's
networking subsystem processed TCP Selective Acknowledgment (SACK)
segments. While processing SACK segments, the Linux kernel's socket buffer
(SKB) data structure becomes fragmented. Each fragment is about TCP maximum
segment size (MSS) bytes. To efficiently process SACK blocks, the Linux
kernel merges multiple fragmented SKBs into one, potentially overflowing
the variable holding the number of segments. A remote attacker could use
this flaw to crash the Linux kernel by sending a crafted sequence of SACK
segments on a TCP connection with small value of TCP MSS, resulting in a
denial of service (DoS). (CVE-2019-11477)

  * Kernel: tcp: excessive resource consumption while processing SACK blocks
allows remote denial of service (CVE-2019-11478)

  * Kernel: tcp: excessive resource consumption for TCP connections with low
MSS allows remote denial of service (CVE-2019-11479)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'kernel' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "bpftool", rpm: "bpftool~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-abi-whitelists", rpm: "kernel-abi-whitelists~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs-devel", rpm: "kernel-tools-libs-devel~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perf", rpm: "perf~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~3.10.0~957.21.3.el7", rls: "CentOS7" ) )){
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

