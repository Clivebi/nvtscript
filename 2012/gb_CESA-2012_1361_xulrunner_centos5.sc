if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-October/018936.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881517" );
	script_version( "2020-08-17T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 08:01:28 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-16 09:45:07 +0530 (Tue, 16 Oct 2012)" );
	script_cve_id( "CVE-2012-4193" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:1361" );
	script_name( "CentOS Update for xulrunner CESA-2012:1361 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xulrunner'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "xulrunner on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "XULRunner provides the XUL Runtime environment for applications using the
  Gecko layout engine.

  A flaw was found in the way XULRunner handled security wrappers. A web page
  containing malicious content could possibly cause an application linked
  against XULRunner (such as Mozilla Firefox) to execute arbitrary code with
  the privileges of the user running the application. (CVE-2012-4193)

  For technical details regarding this flaw, refer to the Mozilla security
  advisories. You can find a link to the Mozilla advisories in the References
  section of this erratum.

  Red Hat would like to thank the Mozilla project for reporting this issue.
  Upstream acknowledges moz_bug_r_a4 as the original reporter.

  All XULRunner users should upgrade to these updated packages, which correct
  this issue. After installing the update, applications using XULRunner must
  be restarted for the changes to take effect." );
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
	if(( res = isrpmvuln( pkg: "xulrunner", rpm: "xulrunner~10.0.8~2.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xulrunner-devel", rpm: "xulrunner-devel~10.0.8~2.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

