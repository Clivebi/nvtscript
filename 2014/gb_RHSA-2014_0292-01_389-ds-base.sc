if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871138" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-03-17 13:48:50 +0530 (Mon, 17 Mar 2014)" );
	script_cve_id( "CVE-2014-0132" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "RedHat Update for 389-ds-base RHSA-2014:0292-01" );
	script_tag( name: "affected", value: "389-ds-base on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "insight", value: "The 389 Directory Server is an LDAPv3 compliant server. The base packages
include the Lightweight Directory Access Protocol (LDAP) server and
command-line utilities for server administration.

It was discovered that the 389 Directory Server did not properly handle
certain SASL-based authentication mechanisms. A user able to authenticate
to the directory using these SASL mechanisms could connect as any other
directory user, including the administrative Directory Manager account.
This could allow them to modify configuration values, as well as read and
write any data the directory holds. (CVE-2014-0132)

All 389-ds-base users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After installing
this update, the 389 server service will be restarted automatically." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2014:0292-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2014-March/msg00020.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the '389-ds-base'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "389-ds-base", rpm: "389-ds-base~1.2.11.15~32.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "389-ds-base-debuginfo", rpm: "389-ds-base-debuginfo~1.2.11.15~32.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "389-ds-base-libs", rpm: "389-ds-base-libs~1.2.11.15~32.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

