if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851761" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-24 05:47:59 +0200 (Thu, 24 May 2018)" );
	script_cve_id( "CVE-2015-1239", "CVE-2017-171479", "CVE-2017-17479", "CVE-2017-17480" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-29 14:51:00 +0000 (Thu, 29 Nov 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for openjpeg2 (openSUSE-SU-2018:1381-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openjpeg2 fixes the following security issues:

  - CVE-2015-1239: A double free vulnerability in the j2k_read_ppm_v3
  function allowed remote attackers to cause a denial of service (crash)
  (bsc#1066713)

  - CVE-2017-17479: A stack-based buffer overflow in the pgxtoimage function
  in jpwl/convert.c could crash the converter. (bsc#1072125)

  - CVE-2017-17480: A stack-based buffer overflow in the pgxtovolume
  function in jp3d/convert.c could crash the converter. (bsc#1072124)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-490=1" );
	script_tag( name: "affected", value: "openjpeg2 on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:1381-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-05/msg00091.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7", rpm: "libopenjp2-7~2.1.0~22.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7-debuginfo", rpm: "libopenjp2-7-debuginfo~2.1.0~22.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2", rpm: "openjpeg2~2.1.0~22.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2-debuginfo", rpm: "openjpeg2-debuginfo~2.1.0~22.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2-debugsource", rpm: "openjpeg2-debugsource~2.1.0~22.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2-devel", rpm: "openjpeg2-devel~2.1.0~22.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7-32bit", rpm: "libopenjp2-7-32bit~2.1.0~22.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7-debuginfo-32bit", rpm: "libopenjp2-7-debuginfo-32bit~2.1.0~22.1", rls: "openSUSELeap42.3" ) )){
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

