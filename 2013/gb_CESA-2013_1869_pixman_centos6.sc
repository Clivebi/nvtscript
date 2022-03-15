if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881849" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-23 12:44:57 +0530 (Mon, 23 Dec 2013)" );
	script_cve_id( "CVE-2013-6425" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "CentOS Update for pixman CESA-2013:1869 centos6" );
	script_tag( name: "affected", value: "pixman on CentOS 6" );
	script_tag( name: "insight", value: "Pixman is a pixel manipulation library for the X Window System and Cairo.

An integer overflow, which led to a heap-based buffer overflow, was found
in the way pixman handled trapezoids. If a remote attacker could trick an
application using pixman into rendering a trapezoid shape with specially
crafted coordinates, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2013-6425)

Users are advised to upgrade to these updated packages, which contain a
backported patch to correct this issue. All applications using pixman
must be restarted for this update to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2013:1869" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-December/020089.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pixman'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
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
	if(( res = isrpmvuln( pkg: "pixman", rpm: "pixman~0.26.2~5.1.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pixman-devel", rpm: "pixman-devel~0.26.2~5.1.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

