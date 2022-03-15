if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-September/017877.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881382" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-07-30 17:38:36 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-2690", "CVE-2011-2692" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-06 15:44:00 +0000 (Thu, 06 Aug 2020)" );
	script_xref( name: "CESA", value: "2011:1104" );
	script_name( "CentOS Update for libpng CESA-2011:1104 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpng'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "libpng on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The libpng packages contain a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  A buffer overflow flaw was found in the way libpng processed certain PNG
  image files. An attacker could create a specially-crafted PNG image that,
  when opened, could cause an application using libpng to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the application. (CVE-2011-2690)

  Note: The application behavior required to exploit CVE-2011-2690 is rarely
  used. No application shipped with Red Hat Enterprise Linux behaves this
  way, for example.

  An uninitialized memory read issue was found in the way libpng processed
  certain PNG images that use the Physical Scale (sCAL) extension. An
  attacker could create a specially-crafted PNG image that, when opened,
  could cause an application using libpng to crash. (CVE-2011-2692)

  Users of libpng should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running applications using
  libpng must be restarted for the update to take effect." );
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
	if(( res = isrpmvuln( pkg: "libpng", rpm: "libpng~1.2.10~7.1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpng-devel", rpm: "libpng-devel~1.2.10~7.1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

