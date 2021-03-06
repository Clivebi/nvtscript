if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-March/msg00040.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870733" );
	script_version( "$Revision: 14114 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-06-06 10:57:24 +0530 (Wed, 06 Jun 2012)" );
	script_cve_id( "CVE-2011-1097" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "RHSA", value: "2011:0390-01" );
	script_name( "RedHat Update for rsync RHSA-2011:0390-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rsync'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "rsync on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "rsync is a program for synchronizing files over a network.

  A memory corruption flaw was found in the way the rsync client processed
  malformed file list data. If an rsync client used the '--recursive' and
  '--delete' options without the '--owner' option when connecting to a
  malicious rsync server, the malicious server could cause rsync on the
  client system to crash or, possibly, execute arbitrary code with the
  privileges of the user running rsync. (CVE-2011-1097)

  Red Hat would like to thank Wayne Davison and Matt McCutchen for reporting
  this issue.

  Users of rsync should upgrade to this updated package, which contains a
  backported patch to resolve this issue." );
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
	if(( res = isrpmvuln( pkg: "rsync", rpm: "rsync~3.0.6~5.el6_0.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsync-debuginfo", rpm: "rsync-debuginfo~3.0.6~5.el6_0.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

