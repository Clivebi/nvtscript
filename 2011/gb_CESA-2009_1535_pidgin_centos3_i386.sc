if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-October/016208.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880668" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2009:1535" );
	script_cve_id( "CVE-2009-2703", "CVE-2009-3083", "CVE-2009-3615" );
	script_name( "CentOS Update for pidgin CESA-2009:1535 centos3 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pidgin'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS3" );
	script_tag( name: "affected", value: "pidgin on CentOS 3" );
	script_tag( name: "insight", value: "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  An invalid pointer dereference bug was found in the way the Pidgin OSCAR
  protocol implementation processed lists of contacts. A remote attacker
  could send a specially-crafted contact list to a user running Pidgin,
  causing Pidgin to crash. (CVE-2009-3615)

  A NULL pointer dereference flaw was found in the way the Pidgin IRC
  protocol plug-in handles IRC topics. A malicious IRC server could send a
  specially-crafted IRC TOPIC message, which once received by Pidgin, would
  lead to a denial of service (Pidgin crash). (CVE-2009-2703)

  A NULL pointer dereference flaw was found in the way the Pidgin MSN
  protocol plug-in handles improper MSNSLP invitations. A remote attacker
  could send a specially-crafted MSNSLP invitation request, which once
  accepted by a valid Pidgin user, would lead to a denial of service (Pidgin
  crash). (CVE-2009-3083)

  All Pidgin users should upgrade to this updated package, which contains
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
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
if(release == "CentOS3"){
	if(( res = isrpmvuln( pkg: "pidgin", rpm: "pidgin~1.5.1~6.el3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

