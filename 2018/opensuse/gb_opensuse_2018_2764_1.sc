if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851899" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-21 08:10:35 +0200 (Fri, 21 Sep 2018)" );
	script_cve_id( "CVE-2017-18233", "CVE-2017-18236", "CVE-2017-18238" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for exempi (openSUSE-SU-2018:2764-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exempi'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for exempi fixes the following security issue:

  - CVE-2017-18236: The ASF_Support::ReadHeaderObject function allowed
  remote attackers to cause a denial of service (infinite loop) via a
  crafted .asf file (bsc#1085589)

  - CVE-2017-18233: Prevent integer overflow in the Chunk class that allowed
  remote attackers to cause a denial of service (infinite loop) via
  crafted XMP data in a .avi file (bsc#1085584)

  - CVE-2017-18238: The TradQT_Manager::ParseCachedBoxes function allowed
  remote attackers to cause a denial of service (infinite loop) via
  crafted XMP data in a .qt file (bsc#1085583)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1022=1" );
	script_tag( name: "affected", value: "exempi on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2764-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00041.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "exempi-debugsource", rpm: "exempi-debugsource~2.2.2~6.8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exempi-tools", rpm: "exempi-tools~2.2.2~6.8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exempi-tools-debuginfo", rpm: "exempi-tools-debuginfo~2.2.2~6.8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexempi-devel", rpm: "libexempi-devel~2.2.2~6.8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexempi3", rpm: "libexempi3~2.2.2~6.8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexempi3-debuginfo", rpm: "libexempi3-debuginfo~2.2.2~6.8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexempi3-32bit", rpm: "libexempi3-32bit~2.2.2~6.8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexempi3-debuginfo-32bit", rpm: "libexempi3-debuginfo-32bit~2.2.2~6.8.1", rls: "openSUSELeap42.3" ) )){
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

