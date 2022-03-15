if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851705" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-20 08:44:45 +0100 (Tue, 20 Feb 2018)" );
	script_cve_id( "CVE-2017-16227", "CVE-2018-5378", "CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:41:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for quagga (openSUSE-SU-2018:0473-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'quagga'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for quagga fixes the following issues:

  - CVE-2017-16227: Fixed bgpd DoS via specially crafted BGP UPDATE messages
  (boo#1065641)

  - CVE-2018-5378: Fixed bgpd bounds check issue via attribute length
  (Quagga-2018-0543, boo#1079798)

  - CVE-2018-5379: Fixed bgpd double free when processing UPDATE message
  (Quagga-2018-1114, boo#1079799)

  - CVE-2018-5380: Fixed bgpd code-to-string conversion tables overrun
  (Quagga-2018-1550, boo#1079800)

  - CVE-2018-5381: Fixed bgpd infinite loop on certain invalid OPEN messages
  (Quagga-2018-1975, boo#1079801)" );
	script_tag( name: "affected", value: "quagga on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:0473-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-02/msg00037.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "libfpm_pb0", rpm: "libfpm_pb0~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfpm_pb0-debuginfo", rpm: "libfpm_pb0-debuginfo~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libospf0", rpm: "libospf0~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libospf0-debuginfo", rpm: "libospf0-debuginfo~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libospfapiclient0", rpm: "libospfapiclient0~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libospfapiclient0-debuginfo", rpm: "libospfapiclient0-debuginfo~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquagga_pb0", rpm: "libquagga_pb0~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquagga_pb0-debuginfo", rpm: "libquagga_pb0-debuginfo~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzebra1", rpm: "libzebra1~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzebra1-debuginfo", rpm: "libzebra1-debuginfo~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "quagga", rpm: "quagga~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "quagga-debuginfo", rpm: "quagga-debuginfo~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "quagga-debugsource", rpm: "quagga-debugsource~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "quagga-devel", rpm: "quagga-devel~1.1.1~18.3.1", rls: "openSUSELeap42.3" ) )){
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

