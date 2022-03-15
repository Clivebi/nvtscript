if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882525" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-02 10:56:13 +0530 (Tue, 02 Aug 2016)" );
	script_cve_id( "CVE-2016-2119" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for samba4 CESA-2016:1487 centos6" );
	script_tag( name: "summary", value: "Check the version of samba4" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Samba is an open-source implementation
of the Server Message Block (SMB) or Common Internet File System (CIFS) protocol,
which allows PC-compatible machines to share files, printers, and other information.

Security Fix(es):

  * A flaw was found in the way Samba initiated signed DCE/RPC connections. A
man-in-the-middle attacker could use this flaw to downgrade the connection
to not use signing and therefore impersonate the server. (CVE-2016-2119)

Red Hat would like to thank the Samba project for reporting this issue.
Upstream acknowledges Stefan Metzmacher as the original reporter." );
	script_tag( name: "affected", value: "samba4 on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1487" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-July/021994.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "samba4", rpm: "samba4~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-client", rpm: "samba4-client~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-common", rpm: "samba4-common~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-dc", rpm: "samba4-dc~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-dc-libs", rpm: "samba4-dc-libs~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-devel", rpm: "samba4-devel~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-libs", rpm: "samba4-libs~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-pidl", rpm: "samba4-pidl~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-python", rpm: "samba4-python~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-test", rpm: "samba4-test~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-winbind", rpm: "samba4-winbind~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-winbind-clients", rpm: "samba4-winbind-clients~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba4-winbind-krb5-locator", rpm: "samba4-winbind-krb5-locator~4.2.10~7.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
