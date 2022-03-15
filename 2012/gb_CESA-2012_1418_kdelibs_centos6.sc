if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-October/018965.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881533" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-11-02 11:01:02 +0530 (Fri, 02 Nov 2012)" );
	script_cve_id( "CVE-2012-4512", "CVE-2012-4513" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-14 16:39:00 +0000 (Fri, 14 Feb 2020)" );
	script_xref( name: "CESA", value: "2012:1418" );
	script_name( "CentOS Update for kdelibs CESA-2012:1418 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kdelibs'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "kdelibs on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The kdelibs packages provide libraries for the K Desktop Environment
  (KDE). Konqueror is a web browser.

  A heap-based buffer overflow flaw was found in the way the CSS (Cascading
  Style Sheets) parser in kdelibs parsed the location of the source for font
  faces. A web page containing malicious content could cause an application
  using kdelibs (such as Konqueror) to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2012-4512)

  A heap-based buffer over-read flaw was found in the way kdelibs calculated
  canvas dimensions for large images. A web page containing malicious content
  could cause an application using kdelibs to crash or disclose portions of
  its memory. (CVE-2012-4513)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The desktop must be restarted (log out,
  then log back in) for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "kdelibs", rpm: "kdelibs~4.3.4~19.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kdelibs-apidocs", rpm: "kdelibs-apidocs~4.3.4~19.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kdelibs-common", rpm: "kdelibs-common~4.3.4~19.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kdelibs-devel", rpm: "kdelibs-devel~4.3.4~19.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
