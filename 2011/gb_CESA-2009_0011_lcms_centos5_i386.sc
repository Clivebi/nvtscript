if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-January/015528.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880712" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:0011" );
	script_cve_id( "CVE-2008-5316", "CVE-2008-5317" );
	script_name( "CentOS Update for lcms CESA-2009:0011 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lcms'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "lcms on CentOS 5" );
	script_tag( name: "insight", value: "Little Color Management System (LittleCMS, or simply 'lcms') is a
  small-footprint, speed-optimized open source color management engine.

  Multiple insufficient input validation flaws were discovered in LittleCMS.
  An attacker could use these flaws to create a specially-crafted image file
  which could cause an application using LittleCMS to crash, or, possibly,
  execute arbitrary code when opened. (CVE-2008-5316, CVE-2008-5317)

  Users of lcms should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running applications using
  lcms library must be restarted for the update to take effect." );
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
	if(( res = isrpmvuln( pkg: "lcms", rpm: "lcms~1.15~1.2.2.el5_2.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lcms-devel", rpm: "lcms-devel~1.15~1.2.2.el5_2.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-lcms", rpm: "python-lcms~1.15~1.2.2.el5_2.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

