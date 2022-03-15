if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883348" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2021-20254" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-24 18:30:00 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-15 03:00:54 +0000 (Tue, 15 Jun 2021)" );
	script_name( "CentOS: Security Advisory for ctdb (CESA-2021:2313)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:2313" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-June/048319.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ctdb'
  package(s) announced via the CESA-2021:2313 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Samba is an open-source implementation of the Server Message Block (SMB)
protocol and the related Common Internet File System (CIFS) protocol, which
allow PC-compatible machines to share files, printers, and various
information.

Security Fix(es):

  * samba: Negative idmap cache entries can cause incorrect group entries in
the Samba file server process token (CVE-2021-20254)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * smb.service stops when samba rpms are updated (BZ#1930747)

  * samba printing dumps core (BZ#1937867)" );
	script_tag( name: "affected", value: "'ctdb' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "ctdb", rpm: "ctdb~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ctdb-tests", rpm: "ctdb-tests~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient", rpm: "libwbclient~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient-devel", rpm: "libwbclient-devel~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-libs", rpm: "samba-client-libs~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common-libs", rpm: "samba-common-libs~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common-tools", rpm: "samba-common-tools~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-dc", rpm: "samba-dc~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-dc-libs", rpm: "samba-dc-libs~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-devel", rpm: "samba-devel~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-krb5-printing", rpm: "samba-krb5-printing~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-pidl", rpm: "samba-pidl~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-python", rpm: "samba-python~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-python-test", rpm: "samba-python-test~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-test", rpm: "samba-test~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-test-libs", rpm: "samba-test-libs~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-vfs-glusterfs", rpm: "samba-vfs-glusterfs~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-clients", rpm: "samba-winbind-clients~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-krb5-locator", rpm: "samba-winbind-krb5-locator~4.10.16~15.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-modules", rpm: "samba-winbind-modules~4.10.16~15.el7_9", rls: "CentOS7" ) )){
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

