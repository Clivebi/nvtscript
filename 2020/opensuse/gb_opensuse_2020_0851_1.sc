if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853223" );
	script_version( "2021-08-13T14:00:52+0000" );
	script_cve_id( "CVE-2019-17566" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 14:00:52 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-23 03:00:55 +0000 (Tue, 23 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for xmlgraphics-batik (openSUSE-SU-2020:0851-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0851-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00042.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xmlgraphics-batik'
  package(s) announced via the openSUSE-SU-2020:0851-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xmlgraphics-batik fixes the following issues:

  - CVE-2019-17566: Fixed a SSRF which might have allowed the underlying
  server to make arbitrary GET requests (bsc#1172961).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-851=1" );
	script_tag( name: "affected", value: "'xmlgraphics-batik' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "xmlgraphics-batik", rpm: "xmlgraphics-batik~1.9~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xmlgraphics-batik-demo", rpm: "xmlgraphics-batik-demo~1.9~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xmlgraphics-batik-rasterizer", rpm: "xmlgraphics-batik-rasterizer~1.9~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xmlgraphics-batik-slideshow", rpm: "xmlgraphics-batik-slideshow~1.9~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xmlgraphics-batik-squiggle", rpm: "xmlgraphics-batik-squiggle~1.9~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xmlgraphics-batik-svgpp", rpm: "xmlgraphics-batik-svgpp~1.9~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xmlgraphics-batik-ttf2svg", rpm: "xmlgraphics-batik-ttf2svg~1.9~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
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

