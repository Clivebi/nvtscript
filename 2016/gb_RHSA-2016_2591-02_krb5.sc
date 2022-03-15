if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871680" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-04 05:41:12 +0100 (Fri, 04 Nov 2016)" );
	script_cve_id( "CVE-2016-3119", "CVE-2016-3120" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for krb5 RHSA-2016:2591-02" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Kerberos is a network authentication system,
which can improve the security of your network by eliminating the insecure practice
of sending passwords over the network in unencrypted form. It allows clients and
servers to authenticate to each other with the help of a trusted third party, the
Kerberos key distribution center (KDC).

The following packages have been upgraded to a newer upstream version: krb5
(1.14.1). (BZ#1292153)

Security Fix(es):

  * A NULL pointer dereference flaw was found in MIT Kerberos kadmind
service. An authenticated attacker with permission to modify a principal
entry could use this flaw to cause kadmind to dereference a null pointer
and crash by supplying an empty DB argument to the modify_principal
command, if kadmind was configured to use the LDAP KDB module.
(CVE-2016-3119)

  * A NULL pointer dereference flaw was found in MIT Kerberos krb5kdc
service. An authenticated attacker could use this flaw to cause krb5kdc to
dereference a null pointer and crash by making an S4U2Self request, if the
restrict_anonymous_to_tgt option was set to true. (CVE-2016-3120)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section." );
	script_tag( name: "affected", value: "krb5 on
  Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:2591-02" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-November/msg00027.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "krb5-debuginfo", rpm: "krb5-debuginfo~1.14.1~26.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.14.1~26.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-libs", rpm: "krb5-libs~1.14.1~26.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-pkinit", rpm: "krb5-pkinit~1.14.1~26.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.14.1~26.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-server-ldap", rpm: "krb5-server-ldap~1.14.1~26.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-workstation", rpm: "krb5-workstation~1.14.1~26.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libkadm5", rpm: "libkadm5~1.14.1~26.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

