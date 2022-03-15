if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871419" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-08-03 15:07:59 +0530 (Mon, 03 Aug 2015)" );
	script_cve_id( "CVE-2015-5477" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for bind97 RHSA-2015:1515-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind97'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
Name System (DNS) protocols. BIND includes a DNS server (named)  a resolver
library (routines for applications to use when interfacing with DNS)  and
tools for verifying that the DNS server is operating correctly.

A flaw was found in the way BIND handled requests for TKEY DNS resource
records. A remote attacker could use this flaw to make named (functioning
as an authoritative DNS server or a DNS resolver) exit unexpectedly with an
assertion failure via a specially crafted DNS request packet.
(CVE-2015-5477)

Red Hat would like to thank ISC for reporting this issue. Upstream
acknowledges Jonathan Foote as the original reporter.

All bind97 users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, the BIND daemon (named) will be restarted automatically." );
	script_tag( name: "affected", value: "bind97 on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:1515-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-July/msg00052.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "bind97", rpm: "bind97~9.7.0~21.P2.el5_11.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-chroot", rpm: "bind97-chroot~9.7.0~21.P2.el5_11.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-debuginfo", rpm: "bind97-debuginfo~9.7.0~21.P2.el5_11.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-devel", rpm: "bind97-devel~9.7.0~21.P2.el5_11.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-libs", rpm: "bind97-libs~9.7.0~21.P2.el5_11.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-utils", rpm: "bind97-utils~9.7.0~21.P2.el5_11.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

