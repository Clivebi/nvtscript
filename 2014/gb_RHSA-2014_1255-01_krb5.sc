if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871246" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-09-18 05:58:21 +0200 (Thu, 18 Sep 2014)" );
	script_cve_id( "CVE-2014-4345" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_name( "RedHat Update for krb5 RHSA-2014:1255-01" );
	script_tag( name: "insight", value: "Kerberos is an authentication system which allows clients and services to
authenticate to each other with the help of a trusted third party, a
Kerberos Key Distribution Center (KDC).

A buffer overflow was found in the KADM5 administration server (kadmind)
when it was used with an LDAP back end for the KDC database. A remote,
authenticated attacker could potentially use this flaw to execute arbitrary
code on the system running kadmind. (CVE-2014-4345)

All krb5 users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, the krb5kdc and kadmind daemons will be restarted
automatically." );
	script_tag( name: "affected", value: "krb5 on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2014:1255-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2014-September/msg00034.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "krb5-debuginfo", rpm: "krb5-debuginfo~1.6.1~80.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.6.1~80.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-libs", rpm: "krb5-libs~1.6.1~80.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.6.1~80.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-server-ldap", rpm: "krb5-server-ldap~1.6.1~80.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-workstation", rpm: "krb5-workstation~1.6.1~80.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

