if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871248" );
	script_version( "$Revision: 12380 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:03:48 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-09-25 05:58:11 +0200 (Thu, 25 Sep 2014)" );
	script_cve_id( "CVE-2014-6271" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "RedHat Update for bash RHSA-2014:1293-01" );
	script_tag( name: "insight", value: "The GNU Bourne Again shell (Bash) is a shell and command language
interpreter compatible with the Bourne shell (sh). Bash is the default
shell for Red Hat Enterprise Linux.

A flaw was found in the way Bash evaluated certain specially crafted
environment variables. An attacker could use this flaw to override or
bypass environment restrictions to execute shell commands. Certain
services and applications allow remote unauthenticated attackers to
provide environment variables, allowing them to exploit this issue.
(CVE-2014-6271)

For additional information on the CVE-2014-6271 flaw, refer to the
linked Knowledgebase article.

Red Hat would like to thank Stephane Chazelas for reporting this issue.

All bash users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue." );
	script_tag( name: "affected", value: "bash on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2014:1293-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2014-September/msg00048.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(7|6|5)" );
	script_xref( name: "URL", value: "https://access.redhat.com/articles/1200223" );
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
	if(( res = isrpmvuln( pkg: "bash", rpm: "bash~4.2.45~5.el7_0.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bash-debuginfo", rpm: "bash-debuginfo~4.2.45~5.el7_0.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "bash", rpm: "bash~4.1.2~15.el6_5.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bash-debuginfo", rpm: "bash-debuginfo~4.1.2~15.el6_5.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "bash", rpm: "bash~3.2~33.el5.1", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bash-debuginfo", rpm: "bash-debuginfo~3.2~33.el5.1", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

