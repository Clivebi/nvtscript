if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-February/msg00057.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870913" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2013-02-22 10:01:17 +0530 (Fri, 22 Feb 2013)" );
	script_cve_id( "CVE-2013-0157" );
	script_bugtraq_id( 57168 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "RHSA", value: "2013:0517-02" );
	script_name( "RedHat Update for util-linux-ng RHSA-2013:0517-02" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'util-linux-ng'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "util-linux-ng on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The util-linux-ng packages contain a large variety of low-level system
  utilities that are necessary for a Linux operating system to function.

  An information disclosure flaw was found in the way the mount command
  reported errors. A local attacker could use this flaw to determine the
  existence of files and directories they do not have access to.
  (CVE-2013-0157)

  These updated util-linux-ng packages include numerous bug fixes and
  enhancements. Space precludes documenting all of these changes in this
  advisory. Users are directed to the Red Hat Enterprise Linux 6.4 Technical
  Notes, linked to in the References, for information on the most significant
  of these changes.

  All users of util-linux-ng are advised to upgrade to these updated
  packages, which contain backported patches to correct these issues and add
  these enhancements." );
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
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "libblkid", rpm: "libblkid~2.17.2~12.9.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libblkid-devel", rpm: "libblkid-devel~2.17.2~12.9.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libuuid", rpm: "libuuid~2.17.2~12.9.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libuuid-devel", rpm: "libuuid-devel~2.17.2~12.9.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "util-linux-ng", rpm: "util-linux-ng~2.17.2~12.9.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "util-linux-ng-debuginfo", rpm: "util-linux-ng-debuginfo~2.17.2~12.9.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "uuidd", rpm: "uuidd~2.17.2~12.9.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

