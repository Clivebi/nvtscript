if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850196" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-08-02 20:28:13 +0530 (Thu, 02 Aug 2012)" );
	script_cve_id( "CVE-2007-6750", "CVE-2012-0031", "CVE-2012-0053" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "openSUSE-SU", value: "2012:0314-1" );
	script_name( "openSUSE: Security Advisory for apache2 (openSUSE-SU-2012:0314-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.4" );
	script_tag( name: "affected", value: "apache2 on openSUSE 11.4" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "This update of apache2 fixes regressions and several
  security problems:

  bnc#728876, fix graceful reload

  bnc#741243, CVE-2012-0031: Fixed a scoreboard corruption
  (shared mem segment) by child causes crash of privileged
  parent (invalid free()) during shutdown.

  bnc#743743, CVE-2012-0053: Fixed an issue in error
  responses that could expose 'httpOnly' cookies when no
  custom ErrorDocument is specified for status code 400'.

  bnc#738855, CVE-2007-6750: The 'mod_reqtimeout' module was
  backported from Apache 2.2.21 to help mitigate the
  'Slowloris' Denial of Service attack.

  You need to enable the 'mod_reqtimeout' module in your
  existing apache configuration to make it effective, e.g. in
  the APACHE_MODULES line in /etc/sysconfig/apache2." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
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
report = "";
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "apache2", rpm: "apache2~2.2.17~4.13.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-devel", rpm: "apache2-devel~2.2.17~4.13.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-certificates", rpm: "apache2-example-certificates~2.2.17~4.13.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-pages", rpm: "apache2-example-pages~2.2.17~4.13.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-itk", rpm: "apache2-itk~2.2.17~4.13.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork", rpm: "apache2-prefork~2.2.17~4.13.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils", rpm: "apache2-utils~2.2.17~4.13.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker", rpm: "apache2-worker~2.2.17~4.13.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-doc", rpm: "apache2-doc~2.2.17~4.13.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

