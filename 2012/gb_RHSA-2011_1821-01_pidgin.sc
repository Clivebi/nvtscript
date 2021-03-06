if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-December/msg00040.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870679" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-09 10:45:55 +0530 (Mon, 09 Jul 2012)" );
	script_cve_id( "CVE-2011-4601", "CVE-2011-4602" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "RHSA", value: "2011:1821-01" );
	script_name( "RedHat Update for pidgin RHSA-2011:1821-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pidgin'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "pidgin on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  An input sanitization flaw was found in the way the AOL Open System for
  Communication in Realtime (OSCAR) protocol plug-in in Pidgin, used by the
  AOL ICQ and AIM instant messaging systems, escaped certain UTF-8
  characters. A remote attacker could use this flaw to crash Pidgin via a
  specially-crafted OSCAR message. (CVE-2011-4601)

  Multiple NULL pointer dereference flaws were found in the Jingle extension
  of the Extensible Messaging and Presence Protocol (XMPP) protocol plug-in
  in Pidgin. A remote attacker could use these flaws to crash Pidgin via a
  specially-crafted Jingle multimedia message. (CVE-2011-4602)

  Red Hat would like to thank the Pidgin project for reporting these issues.
  Upstream acknowledges Evgeny Boger as the original reporter of
  CVE-2011-4601, and Thijs Alkemade as the original reporter of
  CVE-2011-4602.

  All Pidgin users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "libpurple", rpm: "libpurple~2.7.9~3.el6.2", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pidgin", rpm: "pidgin~2.7.9~3.el6.2", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pidgin-debuginfo", rpm: "pidgin-debuginfo~2.7.9~3.el6.2", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

