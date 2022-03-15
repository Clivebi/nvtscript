if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850343" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-12-13 17:02:07 +0530 (Thu, 13 Dec 2012)" );
	script_cve_id( "CVE-2012-2865", "CVE-2012-2866", "CVE-2012-2867", "CVE-2012-2868", "CVE-2012-2869", "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2872" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "openSUSE-SU", value: "2012:1215-1" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2012:1215-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE12\\.1" );
	script_tag( name: "affected", value: "chromium on openSUSE 12.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "Chromium was updated to 21.0.1180.88 to fix various bugs
  and security issues. Security fixes and rewards:

  Please see the referenced Chromium security advisory
  for more detail. Note that the referenced bugs
  may be kept private until a majority of our users are up to
  date with the fix." );
	script_xref( name: "URL", value: "http://sites.google.com/a/chromium.org/dev/Home/chromium-security" );
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
if(release == "openSUSE12.1"){
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~23.0.1255.0~1.34.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~23.0.1255.0~1.34.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~23.0.1255.0~1.34.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~23.0.1255.0~1.34.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~23.0.1255.0~1.34.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-gnome", rpm: "chromium-desktop-gnome~23.0.1255.0~1.34.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-kde", rpm: "chromium-desktop-kde~23.0.1255.0~1.34.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-suid-helper", rpm: "chromium-suid-helper~23.0.1255.0~1.34.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-suid-helper-debuginfo", rpm: "chromium-suid-helper-debuginfo~23.0.1255.0~1.34.1", rls: "openSUSE12.1" ) )){
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

