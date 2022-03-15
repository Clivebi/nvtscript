if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850646" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_cve_id( "CVE-2015-0817", "CVE-2015-0818" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-04-01 07:19:02 +0200 (Wed, 01 Apr 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for seamonkey (openSUSE-SU-2015:0636-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "SeaMonkey was updated to 2.33.1 to fix several vulnerabilities.

  The following vulnerabilities were fixed:

  * Privilege escalation through SVG navigation (CVE-2015-0818)

  * Code execution through incorrect JavaScript bounds checking elimination
  (CVE-2015-0817)" );
	script_tag( name: "affected", value: "seamonkey on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:0636-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.1" );
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
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "seamonkey", rpm: "seamonkey~2.33.1~53.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-debuginfo", rpm: "seamonkey-debuginfo~2.33.1~53.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-debugsource", rpm: "seamonkey-debugsource~2.33.1~53.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-dom-inspector", rpm: "seamonkey-dom-inspector~2.33.1~53.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-irc", rpm: "seamonkey-irc~2.33.1~53.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-translations-common", rpm: "seamonkey-translations-common~2.33.1~53.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "seamonkey-translations-other", rpm: "seamonkey-translations-other~2.33.1~53.1", rls: "openSUSE13.1" ) )){
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

