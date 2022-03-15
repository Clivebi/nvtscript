if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882481" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-06 15:29:34 +0530 (Fri, 06 May 2016)" );
	script_cve_id( "CVE-2016-3068", "CVE-2016-3069" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for emacs-mercurial CESA-2016:0706 centos7" );
	script_tag( name: "summary", value: "Check the version of emacs-mercurial" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mercurial is a fast, lightweight source
control management system designed for efficient handling of very large
distributed projects.

Security Fix(es):

  * It was discovered that Mercurial failed to properly check Git
sub-repository URLs. A Mercurial repository that includes a Git
sub-repository with a specially crafted URL could cause Mercurial to
execute arbitrary code. (CVE-2016-3068)

  * It was discovered that the Mercurial convert extension failed to sanitize
special characters in Git repository names. A Git repository with a
specially crafted name could cause Mercurial to execute arbitrary code when
the Git repository was converted to a Mercurial repository. (CVE-2016-3069)

Red Hat would like to thank Blake Burkhart for reporting these issues." );
	script_tag( name: "affected", value: "emacs-mercurial on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2016:0706" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-May/021855.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "emacs-mercurial", rpm: "emacs-mercurial~2.6.2~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "emacs-mercurial-el", rpm: "emacs-mercurial-el~2.6.2~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mercurial", rpm: "mercurial~2.6.2~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mercurial-hgk", rpm: "mercurial-hgk~2.6.2~6.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

