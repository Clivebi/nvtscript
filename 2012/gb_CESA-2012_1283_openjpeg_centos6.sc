if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-September/018885.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881505" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-22 11:58:24 +0530 (Sat, 22 Sep 2012)" );
	script_cve_id( "CVE-2012-3535" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:1283" );
	script_name( "CentOS Update for openjpeg CESA-2012:1283 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "openjpeg on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "OpenJPEG is an open source library for reading and writing image files in
  JPEG 2000 format.

  It was found that OpenJPEG failed to sanity-check an image header field
  before using it. A remote attacker could provide a specially-crafted image
  file that could cause an application linked against OpenJPEG to crash or,
  possibly, execute arbitrary code. (CVE-2012-3535)

  This issue was discovered by Huzaifa Sidhpurwala of the Red Hat Security
  Response Team.

  Users of OpenJPEG should upgrade to these updated packages, which contain
  a patch to correct this issue. All running applications using OpenJPEG
  must be restarted for the update to take effect." );
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
	if(( res = isrpmvuln( pkg: "openjpeg", rpm: "openjpeg~1.3~9.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openjpeg-devel", rpm: "openjpeg-devel~1.3~9.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openjpeg-libs", rpm: "openjpeg-libs~1.3~9.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

