if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.880737" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:1218" );
	script_cve_id( "CVE-2009-2694" );
	script_name( "CentOS Update for pidgin CESA-2009:1218 centos3 i386" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-August/016101.html" );
	script_xref( name: "URL", value: "http://developer.pidgin.im/wiki/ChangeLog" );
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

  Federico Muttis of Core Security Technologies discovered a flaw in Pidgin's
  MSN protocol handler. If a user received a malicious MSN message, it was
  possible to execute arbitrary code with the permissions of the user running
  Pidgin. (CVE-2009-2694)

  Note: Users can change their privacy settings to only allow messages from
  users on their buddy list to limit the impact of this flaw.

  These packages upgrade Pidgin to version 2.5.9. Refer to the linked Pidgin release
  notes for a full list of changes.

  All Pidgin users should upgrade to these updated packages, which resolve
  this issue. Pidgin must be restarted for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "pidgin", rpm: "pidgin~1.5.1~4.el3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

