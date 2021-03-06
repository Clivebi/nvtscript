if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2010-March/016531.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880587" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2010:0122" );
	script_cve_id( "CVE-2010-0426", "CVE-2010-0427" );
	script_name( "CentOS Update for sudo CESA-2010:0122 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "sudo on CentOS 5" );
	script_tag( name: "insight", value: "The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root.

  A privilege escalation flaw was found in the way sudo handled the sudoedit
  pseudo-command. If a local user were authorized by the sudoers file to use
  this pseudo-command, they could possibly leverage this flaw to execute
  arbitrary code with the privileges of the root user. (CVE-2010-0426)

  The sudo utility did not properly initialize supplementary groups when the
  'runas_default' option (in the sudoers file) was used. If a local user
  were authorized by the sudoers file to perform their sudo commands under
  the account specified with 'runas_default', they would receive the root
  user's supplementary groups instead of those of the intended target user,
  giving them unintended privileges. (CVE-2010-0427)

  Users of sudo should upgrade to this updated package, which contains
  backported patches to correct these issues." );
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "sudo", rpm: "sudo~1.6.9p17~6.el5_4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

