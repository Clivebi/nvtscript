if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883376" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2021-25214" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 09:15:00 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2021-09-02 01:01:06 +0000 (Thu, 02 Sep 2021)" );
	script_name( "CentOS: Security Advisory for bind (CESA-2021:3325)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:3325" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-September/048361.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind'
  package(s) announced via the CESA-2021:3325 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
Name System (DNS) protocols. BIND includes a DNS server (named), a resolver
library (routines for applications to use when interfacing with DNS), and
tools for verifying that the DNS server is operating correctly.

Security Fix(es):

  * bind: Broken inbound incremental zone update (IXFR) can cause named to
terminate unexpectedly (CVE-2021-25214)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'bind' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chroot", rpm: "bind-chroot~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-export-devel", rpm: "bind-export-devel~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-export-libs", rpm: "bind-export-libs~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-lite", rpm: "bind-libs-lite~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-license", rpm: "bind-license~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-lite-devel", rpm: "bind-lite-devel~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-pkcs11", rpm: "bind-pkcs11~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-pkcs11-devel", rpm: "bind-pkcs11-devel~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-pkcs11-libs", rpm: "bind-pkcs11-libs~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-pkcs11-utils", rpm: "bind-pkcs11-utils~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-sdb", rpm: "bind-sdb~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-sdb-chroot", rpm: "bind-sdb-chroot~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.11.4~26.P2.el7_9.7", rls: "CentOS7" ) )){
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

