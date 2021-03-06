if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854159" );
	script_version( "2021-09-22T05:42:45+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 05:42:45 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-14 01:01:55 +0000 (Tue, 14 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for gifsicle (openSUSE-SU-2021:1249-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1249-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7LT4ZGSUVTVP4M6DZMXIWJ67JSPE3CZI" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gifsicle'
  package(s) announced via the openSUSE-SU-2021:1249-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gifsicle fixes the following issues:

     Update to version 1.93:

  * Fix security bug on certain resize operations with `--resize-method=box`

  * Fix problems with colormapless GIFs.

     Update to version 1.92

  * Add `--lossy` option from Kornel Lipiski.

  * Remove an assertion failure possible with `--conserve-memory` +
       `--colors` + `--careful`." );
	script_tag( name: "affected", value: "'gifsicle' package(s) on openSUSE Leap 15.2." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "gifsicle", rpm: "gifsicle~1.93~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gifsicle-debuginfo", rpm: "gifsicle-debuginfo~1.93~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gifsicle-debugsource", rpm: "gifsicle-debugsource~1.93~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
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

