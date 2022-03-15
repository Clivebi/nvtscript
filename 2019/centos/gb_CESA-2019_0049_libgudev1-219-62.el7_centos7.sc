if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882992" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_cve_id( "CVE-2018-15688", "CVE-2018-16864", "CVE-2018-16865" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-01-16 04:01:18 +0100 (Wed, 16 Jan 2019)" );
	script_name( "CentOS Update for libgudev1-219-62.el7_ CESA-2019:0049 centos7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:0049" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-January/023143.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgudev1-219-62.el7'
  package(s) announced via the CESA-2019:0049 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The systemd packages contain systemd, a system and service manager for
Linux, compatible with the SysV and LSB init scripts. It provides
aggressive parallelism capabilities, uses socket and D-Bus activation for
starting services, offers on-demand starting of daemons, and keeps track of
processes using Linux cgroups. In addition, it supports snapshotting and
restoring of the system state, maintains mount and automount points, and
implements an elaborate transactional dependency-based service control
logic. It can also work as a drop-in replacement for sysvinit.

Security Fix(es):

  * systemd: Out-of-bounds heap write in systemd-networkd dhcpv6 option
handling (CVE-2018-15688)

  * systemd: stack overflow when calling syslog from a command with long
cmdline (CVE-2018-16864)

  * systemd: stack overflow when receiving many journald entries
(CVE-2018-16865)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Ubuntu Security Team for reporting
CVE-2018-15688 and Qualys Research Labs for reporting CVE-2018-16864 and
CVE-2018-16865. Upstream acknowledges Felix Wilhelm (Google) as the
original reporter of CVE-2018-15688." );
	script_tag( name: "affected", value: "libgudev1-219-62.el7_ on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "libgudev1", rpm: "libgudev1~219~62.el7_6.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgudev1-devel", rpm: "libgudev1-devel~219~62.el7_6.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~219~62.el7_6.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-devel", rpm: "systemd-devel~219~62.el7_6.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-journal-gateway", rpm: "systemd-journal-gateway~219~62.el7_6.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-libs", rpm: "systemd-libs~219~62.el7_6.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-networkd", rpm: "systemd-networkd~219~62.el7_6.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-python", rpm: "systemd-python~219~62.el7_6.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-resolved", rpm: "systemd-resolved~219~62.el7_6.2", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysv", rpm: "systemd-sysv~219~62.el7_6.2", rls: "CentOS7" ) )){
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

