if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883236" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2020-10711" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-05-22 03:00:59 +0000 (Fri, 22 May 2020)" );
	script_name( "CentOS: Security Advisory for kernel (CESA-2020:2103)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:2103" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-May/035717.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the CESA-2020:2103 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * Kernel: NetLabel: null pointer dereference while receiving CIPSO packet
with null category may cause kernel panic (CVE-2020-10711)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'kernel' package(s) on CentOS 6." );
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
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-abi-whitelists", rpm: "kernel-abi-whitelists~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-firmware", rpm: "kernel-firmware~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perf", rpm: "perf~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~2.6.32~754.29.2.el6", rls: "CentOS6" ) )){
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
