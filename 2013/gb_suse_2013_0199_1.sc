if(description){
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2013-01/msg00025.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.850427" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2013-03-11 18:29:19 +0530 (Mon, 11 Mar 2013)" );
	script_cve_id( "CVE-2012-3174", "CVE-2013-0422" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "openSUSE-SU", value: "2013:0199-1" );
	script_name( "openSUSE: Security Advisory for java-1_7_0-openjdk (openSUSE-SU-2013:0199-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE12\\.2" );
	script_tag( name: "affected", value: "java-1_7_0-openjdk on openSUSE 12.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "java-1_7_0-openjdk was updated to icedtea-2.3.4 fixing bugs
  and  also severe security issues:

  * Security fixes

  - S8004933, CVE-2012-3174: Improve MethodHandle
  interaction with libraries

  - S8006017, CVE-2013-0422: Improve lookup resolutions

  - S8006125: Update MethodHandles library interactions

  * Bug fixes

  - S7197906: BlockOffsetArray::power_to_cards_back() needs
  to handle &> 32 bit shifts

  - G422525: Fix building with PaX enabled kernels.

  - use gpg-offline to check the validity of icedtea tarball

  - use jamvm on %arm

  - use icedtea package name instead of protected openjdk for
  jamvm builds

  - fix armv5 build

  - update to java access bridge 1.26.2

  * bugfix release, mainly 64bit JNI and JVM support

  - fix a segfault in AWT code - (bnc#792951)

  * add openjdk-7-src-b147-awt-crasher.patch

  - turn pulseaudio off on pre 11.4 distros" );
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
if(release == "openSUSE12.2"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk", rpm: "java-1_7_0-openjdk~1.7.0.6~3.20.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debuginfo", rpm: "java-1_7_0-openjdk-debuginfo~1.7.0.6~3.20.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debugsource", rpm: "java-1_7_0-openjdk-debugsource~1.7.0.6~3.20.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo", rpm: "java-1_7_0-openjdk-demo~1.7.0.6~3.20.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo-debuginfo", rpm: "java-1_7_0-openjdk-demo-debuginfo~1.7.0.6~3.20.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel", rpm: "java-1_7_0-openjdk-devel~1.7.0.6~3.20.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel-debuginfo", rpm: "java-1_7_0-openjdk-devel-debuginfo~1.7.0.6~3.20.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-javadoc", rpm: "java-1_7_0-openjdk-javadoc~1.7.0.6~3.20.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-src", rpm: "java-1_7_0-openjdk-src~1.7.0.6~3.20.1", rls: "openSUSE12.2" ) )){
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

