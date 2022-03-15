if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2010-March/016559.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880661" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2010:0141" );
	script_cve_id( "CVE-2007-4476", "CVE-2010-0624" );
	script_name( "CentOS Update for tar CESA-2010:0141 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tar'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "tar on CentOS 5" );
	script_tag( name: "insight", value: "The GNU tar program saves many files together in one archive and can
  restore individual files (or all of the files) from that archive.

  A heap-based buffer overflow flaw was found in the way tar expanded archive
  files. If a user were tricked into expanding a specially-crafted archive,
  it could cause the tar executable to crash or execute arbitrary code with
  the privileges of the user running tar. (CVE-2010-0624)

  Red Hat would like to thank Jakob Lell for responsibly reporting the
  CVE-2010-0624 issue.

  A denial of service flaw was found in the way tar expanded archive files.
  If a user expanded a specially-crafted archive, it could cause the tar
  executable to crash. (CVE-2007-4476)

  Users of tar are advised to upgrade to this updated package, which contains
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
	if(( res = isrpmvuln( pkg: "tar", rpm: "tar~1.15.1~23.0.1.el5_4.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
