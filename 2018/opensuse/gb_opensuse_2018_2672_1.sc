if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851884" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-09 07:09:37 +0200 (Sun, 09 Sep 2018)" );
	script_cve_id( "CVE-2018-16323" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-28 19:59:00 +0000 (Wed, 28 Apr 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for GraphicsMagick (openSUSE-SU-2018:2672-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for GraphicsMagick fixes the following security issue:

  - CVE-2018-16323: ReadXBMImage left data uninitialized when processing an
  XBM file that has a negative pixel value. If the affected code was used
  as a library loaded into a process that includes sensitive information,
  that information sometimes can be leaked via the image data
  (bsc#1106855).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-993=1" );
	script_tag( name: "affected", value: "GraphicsMagick on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2672-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00019.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick", rpm: "GraphicsMagick~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debuginfo", rpm: "GraphicsMagick-debuginfo~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debugsource", rpm: "GraphicsMagick-debugsource~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-devel", rpm: "GraphicsMagick-devel~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-12", rpm: "libGraphicsMagick++-Q16-12~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-12-debuginfo", rpm: "libGraphicsMagick++-Q16-12-debuginfo~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-devel", rpm: "libGraphicsMagick++-devel~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3", rpm: "libGraphicsMagick-Q16-3~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3-debuginfo", rpm: "libGraphicsMagick-Q16-3-debuginfo~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick3-config", rpm: "libGraphicsMagick3-config~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2", rpm: "libGraphicsMagickWand-Q16-2~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2-debuginfo", rpm: "libGraphicsMagickWand-Q16-2-debuginfo~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick", rpm: "perl-GraphicsMagick~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick-debuginfo", rpm: "perl-GraphicsMagick-debuginfo~1.3.25~102.1", rls: "openSUSELeap42.3" ) )){
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

