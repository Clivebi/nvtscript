if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881985" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-08 06:02:17 +0200 (Fri, 08 Aug 2014)" );
	script_cve_id( "CVE-2014-3562" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "CentOS Update for 389-ds-base CESA-2014:1031 centos6" );
	script_tag( name: "affected", value: "389-ds-base on CentOS 6" );
	script_tag( name: "insight", value: "The 389 Directory Server is an LDAPv3 compliant server. The
base packages include the Lightweight Directory Access Protocol (LDAP) server
and command-line utilities for server administration.

It was found that when replication was enabled for each attribute in 389
Directory Server, which is the default configuration, the server returned
replicated metadata when the directory was searched while debugging was
enabled. A remote attacker could use this flaw to disclose potentially
sensitive information. (CVE-2014-3562)

This issue was discovered by Ludwig Krispenz of Red Hat.

All 389-ds-base users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After installing
this update, the 389 server service will be restarted automatically." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:1031" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-August/020477.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the '389-ds-base'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "389-ds-base", rpm: "389-ds-base~1.2.11.15~34.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "389-ds-base-devel", rpm: "389-ds-base-devel~1.2.11.15~34.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "389-ds-base-libs", rpm: "389-ds-base-libs~1.2.11.15~34.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

