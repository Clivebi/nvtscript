if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850545" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2013-12-10 13:21:27 +0530 (Tue, 10 Dec 2013)" );
	script_cve_id( "CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1671", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2013:0946-1)" );
	script_tag( name: "affected", value: "MozillaFirefox on openSUSE 12.3" );
	script_tag( name: "insight", value: "MozillaFirefox was updated to Firefox 21.0 (bnc#819204)

  * MFSA 2013-41/CVE-2013-0801/CVE-2013-1669 Miscellaneous
  memory safety hazards

  * MFSA 2013-42/CVE-2013-1670 (bmo#853709) Privileged access
  for content level constructor

  * MFSA 2013-43/CVE-2013-1671 (bmo#842255) File input
  control has access to full path

  * MFSA 2013-46/CVE-2013-1674 (bmo#860971) Use-after-free
  with video and onresize event

  * MFSA 2013-47/CVE-2013-1675 (bmo#866825) Uninitialized
  functions in DOMSVGZoomEvent

  * MFSA 2013-48/CVE-2013-1676/CVE-2013-1677/CVE-2013-1678/
  CVE-2013-1679/CVE-2013-1680/CVE-2013-1681 Memory
  corruption found using Address Sanitizer

  Changes in MozillaFirefox-branding-openSUSE:

  - modified file locations for Firefox 21 and above

  - added DuckDuckGo as search option (bnc#801121)" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "openSUSE-SU", value: "2013:0946-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE12\\.3" );
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
if(release == "openSUSE12.3"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~21.0~1.18.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-openSUSE", rpm: "MozillaFirefox-branding-openSUSE~21~2.5.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-upstream", rpm: "MozillaFirefox-branding-upstream~21.0~1.18.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-buildsymbols", rpm: "MozillaFirefox-buildsymbols~21.0~1.18.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~21.0~1.18.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~21.0~1.18.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-devel", rpm: "MozillaFirefox-devel~21.0~1.18.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~21.0~1.18.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~21.0~1.18.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr", rpm: "mozilla-nspr~4.9.6~1.7.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-debuginfo", rpm: "mozilla-nspr-debuginfo~4.9.6~1.7.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-debugsource", rpm: "mozilla-nspr-debugsource~4.9.6~1.7.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-devel", rpm: "mozilla-nspr-devel~4.9.6~1.7.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-32bit", rpm: "mozilla-nspr-32bit~4.9.6~1.7.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-nspr-debuginfo-32bit", rpm: "mozilla-nspr-debuginfo-32bit~4.9.6~1.7.1", rls: "openSUSE12.3" ) )){
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

