if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019261.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881616" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-05 09:43:15 +0530 (Tue, 05 Mar 2013)" );
	script_cve_id( "CVE-2012-5519" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2013:0580" );
	script_name( "CentOS Update for cups CESA-2013:0580 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "cups on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The Common UNIX Printing System (CUPS) provides a portable printing layer
  for Linux, UNIX, and similar operating systems.

  It was discovered that CUPS administrative users (members of the
  SystemGroups groups) who are permitted to perform CUPS configuration
  changes via the CUPS web interface could manipulate the CUPS configuration
  to gain unintended privileges. Such users could read or write arbitrary
  files with the privileges of the CUPS daemon, possibly allowing them to
  run arbitrary code with root privileges. (CVE-2012-5519)

  After installing this update, the ability to change certain CUPS
  configuration directives remotely will be disabled by default. The newly
  introduced ConfigurationChangeRestriction directive can be used to enable
  the changing of the restricted directives remotely. Refer to Red Hat
  Bugzilla bug 875898 for more details and the list of restricted directives.

  All users of cups are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing this
  update, the cupsd daemon will be restarted automatically." );
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
	if(( res = isrpmvuln( pkg: "cups", rpm: "cups~1.3.7~30.el5_9.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "cups-devel", rpm: "cups-devel~1.3.7~30.el5_9.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "cups-libs", rpm: "cups-libs~1.3.7~30.el5_9.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "cups-lpd", rpm: "cups-lpd~1.3.7~30.el5_9.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

