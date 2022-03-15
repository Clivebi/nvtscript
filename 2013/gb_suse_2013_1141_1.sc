if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850495" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2013-11-19 14:06:01 +0530 (Tue, 19 Nov 2013)" );
	script_cve_id( "CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1697" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2013:1141-1)" );
	script_tag( name: "affected", value: "MozillaThunderbird on openSUSE 12.2" );
	script_tag( name: "insight", value: "MozillaThunderbird was updated to Thunderbird 17.0.7
  (bnc#825935)

  Security issues fixed:

  * MFSA 2013-49/CVE-2013-1682 Miscellaneous memory safety
  hazards

  * MFSA 2013-50/CVE-2013-1684/CVE-2013-1685/CVE-2013-1686
  Memory corruption found using Address Sanitizer

  * MFSA 2013-51/CVE-2013-1687 (bmo#863933, bmo#866823)
  Privileged content access and execution via XBL

  * MFSA 2013-53/CVE-2013-1690 (bmo#857883) Execution of
  unmapped memory through onreadystatechange event

  * MFSA 2013-54/CVE-2013-1692 (bmo#866915) Data in the
  body of XHR HEAD requests leads to CSRF attacks

  * MFSA 2013-55/CVE-2013-1693 (bmo#711043) SVG filters can
  lead to information disclosure

  * MFSA 2013-56/CVE-2013-1694 (bmo#848535) PreserveWrapper
  has inconsistent behavior

  * MFSA 2013-59/CVE-2013-1697 (bmo#858101) XrayWrappers
  can be bypassed to run user defined methods in a
  privileged context" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "openSUSE-SU", value: "2013:1141-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE12\\.2" );
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
if(release == "openSUSE12.2"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird", rpm: "MozillaThunderbird~17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-buildsymbols", rpm: "MozillaThunderbird-buildsymbols~17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debuginfo", rpm: "MozillaThunderbird-debuginfo~17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debugsource", rpm: "MozillaThunderbird-debugsource~17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-devel", rpm: "MozillaThunderbird-devel~17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-devel-debuginfo", rpm: "MozillaThunderbird-devel-debuginfo~17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-common", rpm: "MozillaThunderbird-translations-common~17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-other", rpm: "MozillaThunderbird-translations-other~17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "enigmail", rpm: "enigmail~1.5.1+17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "enigmail-debuginfo", rpm: "enigmail-debuginfo~1.5.1+17.0.7~49.47.1", rls: "openSUSE12.2" ) )){
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

