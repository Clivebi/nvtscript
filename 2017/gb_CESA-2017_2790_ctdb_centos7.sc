if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882774" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-24 10:00:35 +0200 (Sun, 24 Sep 2017)" );
	script_cve_id( "CVE-2017-12150", "CVE-2017-12151", "CVE-2017-12163" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for ctdb CESA-2017:2790 centos7" );
	script_tag( name: "summary", value: "Check the version of ctdb" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Samba is an open-source implementation of
the Server Message Block (SMB) protocol and the related Common Internet File
System (CIFS) protocol, which allow PC-compatible machines to share files,
printers, and various information.

Security Fix(es):

  * It was found that samba did not enforce 'SMB signing' when certain
configuration options were enabled. A remote attacker could launch a
man-in-the-middle attack and retrieve information in plain-text.
(CVE-2017-12150)

  * A flaw was found in the way samba client used encryption with the max
protocol set as SMB3. The connection could lose the requirement for signing
and encrypting to any DFS redirects, allowing an attacker to read or alter
the contents of the connection via a man-in-the-middle attack.
(CVE-2017-12151)

  * An information leak flaw was found in the way SMB1 protocol was
implemented by Samba. A malicious client could use this flaw to dump server
memory contents to a file on the samba share or to a shared printer, though
the exact area of server memory cannot be controlled by the attacker.
(CVE-2017-12163)

Red Hat would like to thank the Samba project for reporting CVE-2017-12150
and CVE-2017-12151 and Yihan Lian and Zhibin Hu (Qihoo 360 GearTeam),
Stefan Metzmacher (SerNet), and Jeremy Allison (Google) for reporting
CVE-2017-12163. Upstream acknowledges Stefan Metzmacher (SerNet) as the
original reporter of CVE-2017-12150 and CVE-2017-12151." );
	script_tag( name: "affected", value: "ctdb on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:2790" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-September/022546.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "ctdb", rpm: "ctdb~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ctdb-tests", rpm: "ctdb-tests~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libwbclient", rpm: "libwbclient~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libwbclient-devel", rpm: "libwbclient-devel~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba", rpm: "samba~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client-libs", rpm: "samba-client-libs~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common-libs", rpm: "samba-common-libs~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common-tools", rpm: "samba-common-tools~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-dc", rpm: "samba-dc~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-dc-libs", rpm: "samba-dc-libs~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-devel", rpm: "samba-devel~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-krb5-printing", rpm: "samba-krb5-printing~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-pidl", rpm: "samba-pidl~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-python", rpm: "samba-python~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-test", rpm: "samba-test~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-test-libs", rpm: "samba-test-libs~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-vfs-glusterfs", rpm: "samba-vfs-glusterfs~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-clients", rpm: "samba-winbind-clients~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-krb5-locator", rpm: "samba-winbind-krb5-locator~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-modules", rpm: "samba-winbind-modules~4.6.2~11.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

