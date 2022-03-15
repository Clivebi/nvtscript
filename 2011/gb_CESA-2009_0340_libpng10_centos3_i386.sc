if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-March/015649.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880709" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:0340" );
	script_cve_id( "CVE-2009-0040" );
	script_name( "CentOS Update for libpng10 CESA-2009:0340 centos3 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpng10'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS3" );
	script_tag( name: "affected", value: "libpng10 on CentOS 3" );
	script_tag( name: "insight", value: "The libpng packages contain a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  A flaw was discovered in libpng that could result in libpng trying to
  free() random memory if certain, unlikely error conditions occurred. If a
  carefully-crafted PNG file was loaded by an application linked against
  libpng, it could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2009-0040)

  Users of libpng and libpng10 should upgrade to these updated packages,
  which contain backported patches to correct these issues. All running
  applications using libpng or libpng10 must be restarted for the update to
  take effect." );
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
	if(( res = isrpmvuln( pkg: "libpng10", rpm: "libpng10~1.0.13~20", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpng10-devel", rpm: "libpng10-devel~1.0.13~20", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpng", rpm: "libpng~1.2.2~29", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpng-devel", rpm: "libpng-devel~1.2.2~29", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

