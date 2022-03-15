if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881828" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-04 10:10:20 +0530 (Wed, 04 Dec 2013)" );
	script_cve_id( "CVE-2012-5576", "CVE-2013-1913", "CVE-2013-1978" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for gimp CESA-2013:1778 centos5" );
	script_tag( name: "affected", value: "gimp on CentOS 5" );
	script_tag( name: "insight", value: "The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

A stack-based buffer overflow flaw, a heap-based buffer overflow, and an
integer overflow flaw were found in the way GIMP loaded certain X Window
System (XWD) image dump files. A remote attacker could provide a specially
crafted XWD image file that, when processed, would cause the XWD plug-in to
crash or, potentially, execute arbitrary code with the privileges of the
user running the GIMP. (CVE-2012-5576, CVE-2013-1913, CVE-2013-1978)

The CVE-2013-1913 and CVE-2013-1978 issues were discovered by Murray
McAllister of the Red Hat Security Response Team.

Users of the GIMP are advised to upgrade to these updated packages, which
correct these issues. The GIMP must be restarted for the update to take
effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2013:1778" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-December/020040.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gimp'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
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
	if(( res = isrpmvuln( pkg: "gimp", rpm: "gimp~2.2.13~3.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gimp-devel", rpm: "gimp-devel~2.2.13~3.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gimp-libs", rpm: "gimp-libs~2.2.13~3.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

