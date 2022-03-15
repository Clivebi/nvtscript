if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853972" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2020-18032" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-03 06:15:00 +0000 (Sat, 03 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:08:20 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for graphviz (openSUSE-SU-2021:1651-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1651-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GTVENJITKPNO2UD2FTT2WK4SNRNME6PL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'graphviz'
  package(s) announced via the openSUSE-SU-2021:1651-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for graphviz fixes the following issues:

  - CVE-2020-18032: Fixed possible remote code execution via buffer overflow
       (bsc#1185833)." );
	script_tag( name: "affected", value: "'graphviz' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "graphviz", rpm: "graphviz~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-addons-debuginfo", rpm: "graphviz-addons-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-addons-debugsource", rpm: "graphviz-addons-debugsource~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-debuginfo", rpm: "graphviz-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-debugsource", rpm: "graphviz-debugsource~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-devel", rpm: "graphviz-devel~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-doc", rpm: "graphviz-doc~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-gd", rpm: "graphviz-gd~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-gd-debuginfo", rpm: "graphviz-gd-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-gnome", rpm: "graphviz-gnome~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-gnome-debuginfo", rpm: "graphviz-gnome-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-guile", rpm: "graphviz-guile~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-guile-debuginfo", rpm: "graphviz-guile-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-gvedit", rpm: "graphviz-gvedit~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-gvedit-debuginfo", rpm: "graphviz-gvedit-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-java", rpm: "graphviz-java~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-java-debuginfo", rpm: "graphviz-java-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-lua", rpm: "graphviz-lua~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-lua-debuginfo", rpm: "graphviz-lua-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-perl", rpm: "graphviz-perl~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-perl-debuginfo", rpm: "graphviz-perl-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-php", rpm: "graphviz-php~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-php-debuginfo", rpm: "graphviz-php-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-plugins-core", rpm: "graphviz-plugins-core~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-plugins-core-debuginfo", rpm: "graphviz-plugins-core-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-python", rpm: "graphviz-python~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-python-debuginfo", rpm: "graphviz-python-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-ruby", rpm: "graphviz-ruby~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-ruby-debuginfo", rpm: "graphviz-ruby-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-smyrna", rpm: "graphviz-smyrna~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-smyrna-debuginfo", rpm: "graphviz-smyrna-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-tcl", rpm: "graphviz-tcl~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-tcl-debuginfo", rpm: "graphviz-tcl-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphviz6", rpm: "libgraphviz6~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphviz6-debuginfo", rpm: "libgraphviz6-debuginfo~2.40.1~6.9.1", rls: "openSUSELeap15.3" ) )){
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

