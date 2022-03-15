if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851288" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-05-06 15:29:04 +0530 (Fri, 06 May 2016)" );
	script_cve_id( "CVE-2016-1660", "CVE-2016-1661", "CVE-2016-1662", "CVE-2016-1663", "CVE-2016-1664", "CVE-2016-1665", "CVE-2016-1666" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for Chromium (openSUSE-SU-2016:1208-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Chromium was updated to 50.0.2661.94 to fix a number of vulnerabilities
  (boo#977830):

  - CVE-2016-1660: Out-of-bounds write in Blink

  - CVE-2016-1661: Memory corruption in cross-process frames

  - CVE-2016-1662: Use-after-free in extensions

  - CVE-2016-1663: Use-after-free in Blink's V8 bindings

  - CVE-2016-1664: Address bar spoofing

  - CVE-2016-1665: Information leak in V8

  - CVE-2016-1666: Various fixes from internal audits, fuzzing and other
  initiatives" );
	script_tag( name: "affected", value: "Chromium on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1208-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~50.0.2661.94~45.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~50.0.2661.94~45.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~50.0.2661.94~45.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~50.0.2661.94~45.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~50.0.2661.94~45.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-gnome", rpm: "chromium-desktop-gnome~50.0.2661.94~45.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-kde", rpm: "chromium-desktop-kde~50.0.2661.94~45.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-ffmpegsumo", rpm: "chromium-ffmpegsumo~50.0.2661.94~45.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-ffmpegsumo-debuginfo", rpm: "chromium-ffmpegsumo-debuginfo~50.0.2661.94~45.1", rls: "openSUSELeap42.1" ) )){
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

