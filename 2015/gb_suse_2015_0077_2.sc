if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850681" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-09-18 10:37:39 +0200 (Fri, 18 Sep 2015)" );
	script_cve_id( "CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8636", "CVE-2014-8637", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8640", "CVE-2014-8641", "CVE-2014-8642", "CVE-2014-8643" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2015:0077-2)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MozillaFirefox was updated to version 35.0 (bnc#910669)

  Notable features:

  * Firefox Hello with new rooms-based conversations model

  * Implemented HTTP Public Key Pinning Extension (for enhanced
  authentication of encrypted connections)

  Security fixes:

  * MFSA 2015-01/CVE-2014-8634/CVE-2014-8635 Miscellaneous memory safety
  hazards

  * MFSA 2015-02/CVE-2014-8637 (bmo#1094536) Uninitialized memory use during
  bitmap rendering

  * MFSA 2015-03/CVE-2014-8638 (bmo#1080987) sendBeacon requests lack an
  Origin header

  * MFSA 2015-04/CVE-2014-8639 (bmo#1095859) Cookie injection through Proxy
  Authenticate responses

  * MFSA 2015-05/CVE-2014-8640 (bmo#1100409) Read of uninitialized memory in
  Web Audio

  * MFSA 2015-06/CVE-2014-8641 (bmo#1108455) Read-after-free in WebRTC

  * MFSA 2015-07/CVE-2014-8643 (bmo#1114170) (Windows-only) Gecko Media
  Plugin sandbox escape

  * MFSA 2015-08/CVE-2014-8642 (bmo#1079658) Delegated OCSP responder
  certificates failure with id-pkix-ocsp-nocheck extension

  * MFSA 2015-09/CVE-2014-8636 (bmo#987794) XrayWrapper bypass through DOM
  objects

  - obsolete tracker-miner-firefox   0.15 because it leads to startup
  crashes (bnc#908892)" );
	script_tag( name: "affected", value: "MozillaFirefox on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:0077-2" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~35.0~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-upstream", rpm: "MozillaFirefox-branding-upstream~35.0~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-buildsymbols", rpm: "MozillaFirefox-buildsymbols~35.0~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~35.0~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~35.0~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-devel", rpm: "MozillaFirefox-devel~35.0~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~35.0~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~35.0~9.1", rls: "openSUSE13.2" ) )){
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

