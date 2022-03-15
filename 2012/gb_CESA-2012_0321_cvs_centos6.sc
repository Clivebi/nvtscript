if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-February/018453.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881181" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:34:11 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-0804" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2012:0321" );
	script_name( "CentOS Update for cvs CESA-2012:0321 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cvs'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "cvs on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Concurrent Version System (CVS) is a version control system that can record
  the history of your files.

  A heap-based buffer overflow flaw was found in the way the CVS client
  handled responses from HTTP proxies. A malicious HTTP proxy could use this
  flaw to cause the CVS client to crash or, possibly, execute arbitrary code
  with the privileges of the user running the CVS client. (CVE-2012-0804)

  All users of cvs are advised to upgrade to these updated packages, which
  contain a patch to correct this issue." );
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
	if(( res = isrpmvuln( pkg: "cvs", rpm: "cvs~1.11.23~11.el6_2.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

