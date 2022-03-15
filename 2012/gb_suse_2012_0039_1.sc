if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850246" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-08-02 22:40:52 +0530 (Thu, 02 Aug 2012)" );
	script_cve_id( "CVE-2011-3658", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "openSUSE-SU", value: "2012:0039-1" );
	script_name( "openSUSE: Security Advisory for seamonkey (openSUSE-SU-2012:0039-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE11\\.4|openSUSE11\\.3)" );
	script_tag( name: "affected", value: "seamonkey on openSUSE 11.4, openSUSE 11.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "seamonkey version 2.6 fixes several security issues:

  * MFSA 2011-53/CVE-2011-3660: Miscellaneous memory safety
     hazards

  * MFSA 2011-54/CVE-2011-3661: Potentially exploitable crash
    in the YARR regular expression library

  * MFSA 2011-55/CVE-2011-3658: nsSVGValue out-of-bounds
    access

  * MFSA 2011-56/CVE-2011-3663: Key detection without JavaScript
    via SVG animation

  * MFSA 2011-58/CVE-2011-3665: Crash scaling to extreme sizes" );
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
	if(!isnull( res = isrpmvuln( pkg: "seamonkey", rpm: "seamonkey~2.6~0.2.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-dom-inspector", rpm: "seamonkey-dom-inspector~2.6~0.2.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-irc", rpm: "seamonkey-irc~2.6~0.2.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-translations-common", rpm: "seamonkey-translations-common~2.6~0.2.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-translations-other", rpm: "seamonkey-translations-other~2.6~0.2.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-venkman", rpm: "seamonkey-venkman~2.6~0.2.1", rls: "openSUSE11.4" ) )){
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
if(release == "openSUSE11.3"){
	if(!isnull( res = isrpmvuln( pkg: "seamonkey", rpm: "seamonkey~2.6~0.2.1", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-dom-inspector", rpm: "seamonkey-dom-inspector~2.6~0.2.1", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-irc", rpm: "seamonkey-irc~2.6~0.2.1", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-translations-common", rpm: "seamonkey-translations-common~2.6~0.2.1", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-translations-other", rpm: "seamonkey-translations-other~2.6~0.2.1", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-venkman", rpm: "seamonkey-venkman~2.6~0.2.1", rls: "openSUSE11.3" ) )){
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

