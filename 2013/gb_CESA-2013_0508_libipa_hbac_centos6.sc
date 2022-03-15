if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019515.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881679" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-12 10:02:36 +0530 (Tue, 12 Mar 2013)" );
	script_cve_id( "CVE-2013-0219", "CVE-2013-0220" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2013:0508" );
	script_name( "CentOS Update for libipa_hbac CESA-2013:0508 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libipa_hbac'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "libipa_hbac on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The System Security Services Daemon (SSSD) provides a set of daemons to
  manage access to remote directories and authentication mechanisms. It
  provides an NSS and PAM interface toward the system and a pluggable
  back-end system to connect to multiple different account sources. It is
  also the basis to provide client auditing and policy services for projects
  such as FreeIPA.

  A race condition was found in the way SSSD copied and removed user home
  directories. A local attacker who is able to write into the home directory
  of a different user who is being removed could use this flaw to perform
  symbolic link attacks, possibly allowing them to modify and delete
  arbitrary files with the privileges of the root user. (CVE-2013-0219)

  Multiple out-of-bounds memory read flaws were found in the way the autofs
  and SSH service responders parsed certain SSSD packets. An attacker could
  spend a specially-crafted packet that, when processed by the autofs or SSH
  service responders, would cause SSSD to crash. This issue only caused a
  temporary denial of service, as SSSD was automatically restarted by the
  monitor process after the crash. (CVE-2013-0220)

  The CVE-2013-0219 and CVE-2013-0220 issues were discovered by Florian
  Weimer of the Red Hat Product Security Team.

  These updated sssd packages also include numerous bug fixes and
  enhancements. Space precludes documenting all of these changes in this
  advisory. Users are directed to the Red Hat Enterprise Linux 6.4 Technical
  Notes, linked to in the References, for information on the most significant
  of these changes.

  All SSSD users are advised to upgrade to these updated packages, which
  upgrade SSSD to upstream version 1.9 to correct these issues, fix these
  bugs and add these enhancements." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
	if(( res = isrpmvuln( pkg: "libipa_hbac", rpm: "libipa_hbac~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libipa_hbac-devel", rpm: "libipa_hbac-devel~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libipa_hbac-python", rpm: "libipa_hbac-python~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsss_autofs", rpm: "libsss_autofs~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsss_idmap", rpm: "libsss_idmap~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsss_idmap-devel", rpm: "libsss_idmap-devel~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsss_sudo", rpm: "libsss_sudo~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsss_sudo-devel", rpm: "libsss_sudo-devel~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sssd", rpm: "sssd~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sssd-client", rpm: "sssd-client~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sssd-tools", rpm: "sssd-tools~1.9.2~82.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

